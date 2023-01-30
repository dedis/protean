package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"go.dedis.ch/cothority/v3"
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

func init() {
	_, err := onet.GlobalProtocolRegister(VerifyProtoName, NewRandomnessVerify)
	if err != nil {
		log.Errorf("cannot register protocol: %v", err)
		panic(err)
	}
	network.RegisterMessages(&VerifyRandomness{}, &VerifyRandomnessResponse{})
}

type RandomnessVerify struct {
	*onet.TreeNodeInstance

	Data           *Data
	BlsPublic      kyber.Point
	BlsPublics     []kyber.Point
	BlsSk          kyber.Scalar
	FinalSignature blscosi.BlsSignature

	Threshold int
	Failures  int
	Verified  chan bool

	suite     *pairing.SuiteBn256
	responses []VerifyRandomnessResponse
	mask      *sign.Mask
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewRandomnessVerify(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	rv := &RandomnessVerify{
		TreeNodeInstance: n,
		Verified:         make(chan bool, 1),
		suite:            pairing.NewSuiteBn256(),
	}
	err := rv.RegisterHandlers(rv.verifyRandomness, rv.verifyRandomnessResponse)
	if err != nil {
		return nil, err
	}
	return rv, nil
}

func (rv *RandomnessVerify) Start() error {
	var err error
	if rv.Data == nil {
		rv.finish(false)
		return xerrors.New("initialize Data first")
	}
	hash, err := rv.CalculateHash()
	if err != nil {
		log.Errorf("root %s failed to calculate the hash: %v", rv.Name(), err)
		rv.finish(false)
		return err
	}
	resp, err := rv.generateResponse(hash)
	if err != nil {
		log.Errorf("root %s failed to generate response: %v", rv.Name(), err)
		rv.finish(false)
		return err
	}
	rv.responses = append(rv.responses, resp)
	rv.mask, err = sign.NewMask(rv.suite, rv.BlsPublics, rv.BlsPublic)
	if err != nil {
		rv.finish(false)
		return xerrors.Errorf("couldn't generate mask: %v", err)
	}
	vp := &VerifyRandomness{
		Hash: hash,
	}
	rv.timeout = time.AfterFunc(2*time.Minute, func() {
		log.Lvl1("RandomnessVerify protocol timeout")
		rv.finish(false)
	})
	errs := rv.Broadcast(vp)
	if len(errs) > (len(rv.Roster().List) - rv.Threshold) {
		log.Errorf("some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (rv *RandomnessVerify) verifyRandomness(r structVerifyRandomness) error {
	defer rv.Done()
	//hash, err := CalculateHash(rv.Data)
	hash, err := rv.CalculateHash()
	if err != nil {
		log.Errorf("%s: couldn't calculate the hash: %v", rv.Name(), err)
		return cothority.ErrorOrNil(rv.SendToParent(&VerifyRandomnessResponse{}),
			"sending VerifyRandomnessResponse to parent")
	}
	if !bytes.Equal(hash, r.Hash) {
		log.Errorf("%s: hashes do not match", rv.Name())
		return cothority.ErrorOrNil(rv.SendToParent(&VerifyRandomnessResponse{}),
			"sending VerifyRandomnessResponse to parent")
	}
	resp, err := rv.generateResponse(hash)
	if err != nil {
		log.Errorf("%s couldn't generate response: %v", rv.Name(), err)
	}
	return cothority.ErrorOrNil(rv.SendToParent(&resp),
		"sending VerifyRandomnessResponse to parent")
}

func (rv *RandomnessVerify) verifyRandomnessResponse(r structVerifyRandomnessResponse) error {
	index := searchPublicKey(rv.TreeNodeInstance, r.ServerIdentity)
	if len(r.Signature) == 0 || index < 0 {
		log.Lvl2(r.ServerIdentity, "refused to respond")
		rv.Failures++
		if rv.Failures > (len(rv.Roster().List) - rv.Threshold) {
			log.Lvl2(r.ServerIdentity, "couldn't get enough responses")
			rv.finish(false)
		}
		return nil
	}

	rv.mask.SetBit(index, true)
	rv.responses = append(rv.responses, r.VerifyRandomnessResponse)

	if len(rv.responses) == rv.Threshold {
		finalSignature := rv.suite.G1().Point()
		for _, resp := range rv.responses {
			sig, err := resp.Signature.Point(rv.suite)
			if err != nil {
				rv.finish(false)
				return err
			}
			finalSignature = finalSignature.Add(finalSignature, sig)
		}
		sig, err := finalSignature.MarshalBinary()
		if err != nil {
			rv.finish(false)
			return err
		}
		rv.FinalSignature = append(sig, rv.mask.Mask()...)
		rv.finish(true)
	}
	return nil
}

func (rv *RandomnessVerify) CalculateHash() ([]byte, error) {
	h := sha256.New()
	buf, err := rv.Data.Public.MarshalBinary()
	if err != nil {
		return nil, err
	}
	h.Write(buf)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(rv.Data.Round))
	h.Write(b)
	h.Write(rv.Data.Prev)
	h.Write(rv.Data.Value)
	return h.Sum(nil), nil
}

func (rv *RandomnessVerify) generateResponse(data []byte) (VerifyRandomnessResponse, error) {
	sig, err := bls.Sign(rv.suite, rv.BlsSk, data)
	if err != nil {
		return VerifyRandomnessResponse{}, err
	}
	return VerifyRandomnessResponse{Signature: sig}, nil
}

func searchPublicKey(p *onet.TreeNodeInstance, servID *network.ServerIdentity) int {
	for idx, si := range p.Roster().List {
		if si.Equal(servID) {
			return idx
		}
	}
	return -1
}

func (rv *RandomnessVerify) finish(result bool) {
	rv.timeout.Stop()
	select {
	case rv.Verified <- result:
		// succeeded
	default:
		// would have blocked because some other call to finish()
		// beat us.
	}
	rv.doneOnce.Do(func() { rv.Done() })
}
