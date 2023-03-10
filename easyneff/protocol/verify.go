package protocol

import (
	"sync"
	"time"

	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/blscosi"
	blsproto "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3/util/key"

	"github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
)

func init() {
	_, err := onet.GlobalProtocolRegister(VerifyProtoName, NewShuffleVerify)
	if err != nil {
		log.Errorf("cannot register protocol: %v", err)
		panic(err)
	}
}

type ShuffleVerify struct {
	*onet.TreeNodeInstance

	ShufInput   *base.ShuffleInput
	ShufOutput  *base.ShuffleOutput
	ExecReq     *core.ExecutionRequest
	InputHashes map[string][]byte

	KP             *key.Pair
	InputReceipts  map[string]*core.OpcodeReceipt
	OutputReceipts map[string]*core.OpcodeReceipt

	ShufVerify VerificationFn

	Threshold int
	Failures  int
	Verified  chan bool

	suite     *pairing.SuiteBn256
	responses []*VerifyProofsResponse
	mask      *sign.Mask
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewShuffleVerify(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	s := &ShuffleVerify{
		TreeNodeInstance: n,
		Verified:         make(chan bool, 1),
		InputReceipts:    make(map[string]*core.OpcodeReceipt),
		OutputReceipts:   make(map[string]*core.OpcodeReceipt),
		suite:            pairing.NewSuiteBn256(),
	}
	err := s.RegisterHandlers(s.verifyProofs, s.verifyProofsResponse)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ShuffleVerify) Start() error {
	if s.ExecReq == nil {
		s.finish(false)
		return xerrors.New("missing execution request")
	}
	if len(s.ShufOutput.Proofs) == 0 {
		s.finish(false)
		return xerrors.New("initialize Proofs first")
	}
	err := s.runVerification()
	if err != nil {
		log.Errorf("%s couldn't verify the execution request: %v", s.Name(), err)
		s.finish(false)
		return err
	}
	resp, err := s.generateResponse()
	if err != nil {
		log.Errorf("%s failed to generate response: %v", s.Name(), err)
		s.finish(false)
		return err
	}
	s.responses = append(s.responses, resp)
	s.mask, err = sign.NewMask(s.suite, s.Roster().ServicePublics(blscosi.ServiceName), s.KP.Public)
	if err != nil {
		log.Errorf("couldn't generate mask: %v", err)
		s.finish(false)
		return err
	}
	vp := &VerifyProofs{
		ShufInput:  s.ShufInput,
		ShufOutput: s.ShufOutput,
		ExecReq:    s.ExecReq,
	}
	s.timeout = time.AfterFunc(15*time.Minute, func() {
		log.Lvl1("ShuffleVerify protocol timeout")
		s.finish(false)
	})
	errs := s.Broadcast(vp)
	if len(errs) > (len(s.Roster().List) - s.Threshold) {
		log.Errorf("some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (s *ShuffleVerify) verifyProofs(r structVerifyProofs) error {
	defer s.Done()
	var err error
	s.ShufInput = r.ShufInput
	s.ShufOutput = r.ShufOutput
	s.ExecReq = r.ExecReq
	s.InputHashes, err = s.ShufInput.PrepareHashes()
	err = s.runVerification()
	if err != nil {
		log.Errorf("%s couldn't verify the execution request: %v", s.Name(), err)
		s.finish(false)
		return err
	}
	err = s.ShufVerify(s.ShufOutput, nil, r.ShufInput.H, r.ShufInput.Pairs,
		s.Roster().Publics())
	if err != nil {
		log.Lvl2(s.ServerIdentity(), "failed to verify the proofs")
		return cothority.ErrorOrNil(s.SendToParent(&VerifyProofsResponse{}),
			"sending VerifyProofsResponse to parent")
	}
	resp, err := s.generateResponse()
	if err != nil {
		log.Errorf("%s couldn't generate response: %v", s.Name(), err)
	}
	return cothority.ErrorOrNil(s.SendToParent(resp),
		"sending VerifyProofsResponse to parent")
}

func (s *ShuffleVerify) verifyProofsResponse(r structVerifyProofsResponse) error {
	index := utils.SearchPublicKey(s.TreeNodeInstance, r.ServerIdentity)
	if len(r.OutSignatures) == 0 || index < 0 {
		log.Lvl2(r.ServerIdentity, "refused to respond")
		s.Failures++
		if s.Failures > (len(s.Roster().List) - s.Threshold) {
			log.Lvl2(s.ServerIdentity, "couldn't get enough responses")
			s.finish(false)
		}
		return nil
	}

	s.mask.SetBit(index, true)
	s.responses = append(s.responses, &r.VerifyProofsResponse)
	if len(s.responses) == s.Threshold {
		for name, receipt := range s.OutputReceipts {
			aggSignature := s.suite.G1().Point()
			for _, resp := range s.responses {
				sig, err := resp.OutSignatures[name].Point(s.suite)
				if err != nil {
					s.finish(false)
					return err
				}
				aggSignature = aggSignature.Add(aggSignature, sig)
			}
			sig, err := aggSignature.MarshalBinary()
			if err != nil {
				s.finish(false)
				return err
			}
			receipt.Sig = append(sig, s.mask.Mask()...)
		}
		for name, receipt := range s.InputReceipts {
			aggSignature := s.suite.G1().Point()
			for _, resp := range s.responses {
				sig, err := resp.InSignatures[name].Point(s.suite)
				if err != nil {
					s.finish(false)
					return err
				}
				aggSignature = aggSignature.Add(aggSignature, sig)
			}
			sig, err := aggSignature.MarshalBinary()
			if err != nil {
				s.finish(false)
				return err
			}
			receipt.Sig = append(sig, s.mask.Mask()...)
		}
		s.finish(true)
	}
	return nil
}

func (s *ShuffleVerify) generateResponse() (*VerifyProofsResponse, error) {
	inSigs := make(map[string]blsproto.BlsSignature)
	outSigs := make(map[string]blsproto.BlsSignature)
	epid := s.ExecReq.EP.Hash()
	opIdx := s.ExecReq.Index
	hash, err := s.ShufOutput.Hash()
	if err != nil {
		return &VerifyProofsResponse{}, err
	}
	r := &core.OpcodeReceipt{
		EPID:      epid,
		OpIdx:     opIdx,
		Name:      "proofs",
		HashBytes: hash,
	}
	if s.IsRoot() {
		s.OutputReceipts["proofs"] = r
	}
	sig, err := bls.Sign(s.suite, s.KP.Private, r.Hash())
	if err != nil {
		return &VerifyProofsResponse{}, err
	}
	outSigs["proofs"] = sig
	// Input receipts
	for inputName, inputHash := range s.InputHashes {
		r := core.OpcodeReceipt{
			EPID:      epid,
			OpIdx:     opIdx,
			Name:      inputName,
			HashBytes: inputHash,
		}
		sig, err := bls.Sign(s.suite, s.KP.Private, r.Hash())
		if err != nil {
			return &VerifyProofsResponse{}, err
		}
		inSigs[inputName] = sig
		if s.IsRoot() {
			s.InputReceipts[inputName] = &r
		}
	}
	return &VerifyProofsResponse{InSignatures: inSigs,
		OutSignatures: outSigs}, nil
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

func (s *ShuffleVerify) runVerification() error {
	vData := &core.VerificationData{
		UID:         base.UID,
		OpcodeName:  base.SHUFFLE,
		InputHashes: s.InputHashes,
	}
	return s.ExecReq.Verify(vData)
}
