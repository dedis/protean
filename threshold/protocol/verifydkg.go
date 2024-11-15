package protocol

import (
	"bytes"
	"go.dedis.ch/cothority/v3/blscosi/bdnproto"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"sync"
	"time"

	"github.com/dedis/protean/core"
	"github.com/dedis/protean/threshold/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
)

func init() {
	_, err := onet.GlobalProtocolRegister(VerifyDKGProtoName, NewVerifyDKG)
	if err != nil {
		log.Errorf("cannot register protocol: %v", err)
		panic(err)
	}
}

type VerifyDKG struct {
	*onet.TreeNodeInstance

	DKGID    [32]byte
	X        kyber.Point
	ExecReq  *core.ExecutionRequest
	KP       *key.Pair
	Receipts map[string]*core.OpcodeReceipt

	Threshold int
	Success   int
	Failures  int
	Verified  chan bool

	responses []*VerifyResponse
	suite     *bn256.Suite
	mask      *sign.Mask
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewVerifyDKG(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	v := &VerifyDKG{
		TreeNodeInstance: n,
		Verified:         make(chan bool, 1),
		Receipts:         make(map[string]*core.OpcodeReceipt),
		suite:            bn256.NewSuite(),
		responses:        make([]*VerifyResponse, len(n.Roster().List)),
	}
	err := v.RegisterHandlers(v.verifyDKG, v.verifyDKGResponse)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (v *VerifyDKG) Start() error {
	if v.ExecReq == nil {
		v.finish(false)
		return xerrors.New("missing execution request")
	}
	err := v.runVerification()
	if err != nil {
		log.Errorf("%s couldn't verify the execution request: %v:", v.Name(), err)
		v.finish(false)
		return err
	}
	resp, err := v.generateResponse()
	if err != nil {
		log.Errorf("%s failed to generate response: %v", v.Name(), err)
		v.finish(false)
		return err
	}
	v.responses[v.Index()] = resp
	v.Success++
	v.mask, err = sign.NewMask(v.suite, v.Roster().ServicePublics(blscosi.ServiceName), v.KP.Public)
	if err != nil {
		v.finish(false)
		return xerrors.Errorf("couldn't generate mask: %v", err)
	}
	vr := &VerifyRequest{ExecReq: v.ExecReq}
	v.timeout = time.AfterFunc(5*time.Minute, func() {
		log.Lvl1("verifydkg protocol timeout")
		v.finish(false)
	})
	errs := v.SendToChildrenInParallel(vr)
	if len(errs) > (len(v.Roster().List) - v.Threshold) {
		log.Errorf("some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (v *VerifyDKG) verifyDKG(r structVerifyRequest) error {
	defer v.Done()
	v.ExecReq = r.ExecReq
	if !bytes.Equal(v.DKGID[:], v.ExecReq.EP.CID) {
		log.Errorf("%s: DKGID does not match CID", v.Name())
		return cothority.ErrorOrNil(v.SendToParent(&VerifyResponse{}),
			"sending VerifyResponse to parent")
	}
	err := v.runVerification()
	if err != nil {
		log.Errorf("%s couldn't verify the execution request: %v:", v.Name(), err)
		return cothority.ErrorOrNil(v.SendToParent(&VerifyResponse{}),
			"sending VerifyResponse to parent")
	}
	resp, err := v.generateResponse()
	if err != nil {
		log.Errorf("%s failed to generate response: %v", v.Name(), err)
	}
	return cothority.ErrorOrNil(v.SendToParent(resp),
		"sending VerifyProofs to parent")
}

func (v *VerifyDKG) verifyDKGResponse(r structVerifyResponse) error {
	index := utils.SearchPublicKey(v.TreeNodeInstance, r.ServerIdentity)
	if len(r.Signatures) == 0 || index < 0 {
		log.Lvl2(r.ServerIdentity, "refused to respond")
		v.Failures++
		if v.Failures > (len(v.Roster().List) - v.Threshold) {
			log.Lvl2(v.ServerIdentity, "couldn't get enough responses")
			v.finish(false)
		}
		return nil
	}

	v.mask.SetBit(index, true)
	v.responses[r.RosterIndex] = &r.VerifyResponse
	v.Success++
	if v.Success == v.Threshold {
		for name, receipt := range v.Receipts {
			var partialSigs [][]byte
			for _, resp := range v.responses {
				if resp != nil {
					partialSigs = append(partialSigs, resp.Signatures[name])
				}
			}
			aggSig, err := bdn.AggregateSignatures(v.suite, partialSigs, v.mask)
			if err != nil {
				log.Error(err)
				v.finish(false)
				return err
			}
			sig, err := aggSig.MarshalBinary()
			if err != nil {
				log.Error(err)
				v.finish(false)
				return err
			}
			receipt.Sig = append(sig, v.mask.Mask()...)
		}
		v.finish(true)
	}
	return nil
}

func (v *VerifyDKG) generateResponse() (*VerifyResponse, error) {
	hash, err := utils.HashPoint(v.X)
	if err != nil {
		return &VerifyResponse{}, err
	}
	r := &core.OpcodeReceipt{
		EPID:      v.ExecReq.EP.Hash(),
		OpIdx:     v.ExecReq.Index,
		Name:      "X",
		HashBytes: hash,
	}
	if v.IsRoot() {
		v.Receipts["X"] = r
	}
	sig, err := bdn.Sign(v.suite, v.KP.Private, r.Hash())
	if err != nil {
		return &VerifyResponse{}, err
	}
	sigs := make(map[string]bdnproto.BdnSignature)
	sigs["X"] = sig
	return &VerifyResponse{Signatures: sigs}, nil
}

func (v *VerifyDKG) runVerification() error {
	vData := &core.VerificationData{
		UID:        base.UID,
		OpcodeName: base.DKG,
	}
	return v.ExecReq.Verify(vData)
}

func (v *VerifyDKG) finish(result bool) {
	v.timeout.Stop()
	select {
	case v.Verified <- result:
		// succeeded
	default:
		// would have blocked because some other call to finish()
		// beat us.
	}
	v.doneOnce.Do(func() { v.Done() })
}
