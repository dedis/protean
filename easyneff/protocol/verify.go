package protocol

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/dedis/protean/utils"
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
	_, err := onet.GlobalProtocolRegister(ShuffleVerifyName, NewShuffleVerify)
	if err != nil {
		log.Errorf("cannot register protocol: %v", err)
		panic(err)
	}
	network.RegisterMessages(&VerifyProofs{}, &VerifyProofsResponse{})
}

type ShuffleVerify struct {
	*onet.TreeNodeInstance

	Pairs  []utils.ElGamalPair
	H      kyber.Point
	SProof ShuffleProof
	Verify VerificationFn

	Publics        []kyber.Point
	BlsPublic      kyber.Point
	BlsPublics     []kyber.Point
	BlsSk          kyber.Scalar
	FinalSignature blscosi.BlsSignature

	Threshold int
	Failures  int
	Verified  chan bool

	suite     *pairing.SuiteBn256
	responses []VerifyProofsResponse
	mask      *sign.Mask
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewShuffleVerify(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	s := &ShuffleVerify{
		TreeNodeInstance: n,
		Verified:         make(chan bool, 1),
		suite:            pairing.NewSuiteBn256(),
	}
	err := s.RegisterHandlers(s.verifyProofs, s.verifyProofsReply)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ShuffleVerify) Start() error {
	var err error
	if len(s.SProof.Proofs) == 0 {
		s.finish(false)
		return xerrors.New("initialize Proofs first")
	}
	s.mask, err = sign.NewMask(s.suite, s.BlsPublics, s.BlsPublic)
	if err != nil {
		s.finish(false)
		return xerrors.Errorf("couldn't generate mask: %v", err)
	}
	hash, err := CalculateHash(s.SProof.Proofs)
	if err != nil {
		log.Errorf("Root %s failed to calculate the hash: %v", s.Name(), err)
		s.finish(false)
		return err
	}
	reply, err := s.generateResponse(hash)
	if err != nil {
		log.Errorf("Root %s failed to generate reply: %v", s.Name(), err)
		s.finish(false)
		return err
	}
	s.responses = append(s.responses, reply)
	vp := &VerifyProofs{
		Pairs:  s.Pairs,
		H:      s.H,
		SProof: s.SProof,
		Hash:   hash,
	}
	s.timeout = time.AfterFunc(2*time.Minute, func() {
		log.Lvl1("ThreshDecrypt protocol timeout")
		s.finish(false)
	})
	errs := s.Broadcast(vp)
	if len(errs) > (len(s.Roster().List) - s.Threshold) {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return errors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (s *ShuffleVerify) verifyProofs(r structVerifyProofs) error {
	defer s.Done()
	err := s.Verify(&r.SProof, nil, r.H, r.Pairs, s.Publics)
	if err != nil {
		log.Lvl2(s.ServerIdentity(), "failed to verify the proofs")
		return cothority.ErrorOrNil(s.SendToParent(&VerifyProofsResponse{}),
			"sending VerifyProofsResponse to parent")
	}
	hash, err := CalculateHash(r.SProof.Proofs)
	if err != nil {
		log.Errorf("%s couldn't calculate the hash: %v", s.Name(), err)
		return cothority.ErrorOrNil(s.SendToParent(&VerifyProofsResponse{}),
			"sending VerifyProofsResponse to parent")
	}
	if !bytes.Equal(r.Hash, hash) {
		log.Errorf("%s: hashes do not match", s.Name())
		return cothority.ErrorOrNil(s.SendToParent(&VerifyProofsResponse{}),
			"sending VerifyProofsResponse to parent")
	}
	reply, err := s.generateResponse(hash)
	if err != nil {
		log.Errorf("%s couldn't generate reply: %v", s.Name(), err)
	}
	return cothority.ErrorOrNil(s.SendToParent(&reply),
		"sending VerifyProofsResponse to parent")
}

func (s *ShuffleVerify) verifyProofsReply(r structVerifyProofsResponse) error {
	if len(r.Signature) == 0 {
		log.Lvl2("Node", r.ServerIdentity, "refused to reply")
		s.Failures++
		if s.Failures > (len(s.Roster().List) - s.Threshold) {
			log.Lvl2(r.ServerIdentity, "couldn't get enough responses")
			s.finish(false)
		}
		return nil
	}
	_, index := searchPublicKey(s.TreeNodeInstance, r.ServerIdentity)
	s.mask.SetBit(index, true)
	s.responses = append(s.responses, r.VerifyProofsResponse)
	if len(s.responses) == s.Threshold {
		finalSignature := s.suite.G1().Point()
		for _, resp := range s.responses {
			sig, err := resp.Signature.Point(s.suite)
			if err != nil {
				s.finish(false)
				return err
			}
			finalSignature = finalSignature.Add(finalSignature, sig)
		}
		sig, err := finalSignature.MarshalBinary()
		if err != nil {
			s.finish(false)
			return err
		}
		s.FinalSignature = append(sig, s.mask.Mask()...)
		s.finish(true)
	}
	return nil
}

func (s *ShuffleVerify) generateResponse(data []byte) (VerifyProofsResponse, error) {
	sig, err := bls.Sign(s.suite, s.BlsSk, data)
	if err != nil {
		return VerifyProofsResponse{}, err
	}
	return VerifyProofsResponse{Signature: sig}, nil
}

func CalculateHash(proofs []Proof) ([]byte, error) {
	h := sha256.New()
	for _, pr := range proofs {
		for _, pair := range pr.Pairs {
			kbuf, err := pair.K.MarshalBinary()
			if err != nil {
				return nil, err
			}
			cbuf, err := pair.C.MarshalBinary()
			if err != nil {
				return nil, err
			}
			h.Write(kbuf)
			h.Write(cbuf)
		}
		h.Write(pr.Proof)
		h.Write(pr.Signature)
	}
	return h.Sum(nil), nil
}

func searchPublicKey(p *onet.TreeNodeInstance, servID *network.ServerIdentity) (
	kyber.Point, int) {
	for idx, si := range p.Roster().List {
		if si.Equal(servID) {
			return p.NodePublic(si), idx
		}
	}
	return nil, -1
}

func (s *ShuffleVerify) finish(result bool) {
	s.timeout.Stop()
	select {
	case s.Verified <- result:
		// succeeded
	default:
		// would have blocked because some other call to finish()
		// beat us.
	}
	s.doneOnce.Do(func() { s.Done() })
}
