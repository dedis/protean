package protocol

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/blscosi"
	blsproto "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3/util/key"
	"sync"
	"time"

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

	ShufInput *base.ShuffleInput
	ShufProof *ShuffleProof
	ExecReq   *core.ExecutionRequest
	KP        *key.Pair
	Receipts  map[string]*core.OpcodeReceipt

	Verify VerificationFn

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
		suite:            pairing.NewSuiteBn256(),
	}
	err := s.RegisterHandlers(s.verifyProofs, s.verifyProofsResponse)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ShuffleVerify) Start() error {
	if len(s.ShufProof.Proofs) == 0 {
		s.finish(false)
		return xerrors.New("initialize Proofs first")
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
		ShufInput: s.ShufInput,
		ShufProof: s.ShufProof,
		ExecReq:   s.ExecReq,
	}
	s.timeout = time.AfterFunc(2*time.Minute, func() {
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
	s.ShufProof = r.ShufProof
	s.ExecReq = r.ExecReq
	err := s.Verify(s.ShufProof, nil, r.ShufInput.H, r.ShufInput.Pairs,
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
	if len(r.Signatures) == 0 || index < 0 {
		log.Lvl2(r.ServerIdentity, "refused to respond")
		s.Failures++
		if s.Failures > (len(s.Roster().List) - s.Threshold) {
			log.Lvl2(r.ServerIdentity, "couldn't get enough responses")
			s.finish(false)
		}
		return nil
	}

	s.mask.SetBit(index, true)
	s.responses = append(s.responses, &r.VerifyProofsResponse)
	if len(s.responses) == s.Threshold {
		for name, receipt := range s.Receipts {
			aggSignature := s.suite.G1().Point()
			for _, resp := range s.responses {
				sig, err := resp.Signatures[name].Point(s.suite)
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
	hash, err := s.ShufProof.Hash()
	if err != nil {
		return &VerifyProofsResponse{}, err
	}
	r := &core.OpcodeReceipt{
		EPID:      s.ExecReq.EP.Hash(),
		OpIdx:     s.ExecReq.Index,
		Name:      "proofs",
		HashBytes: hash,
	}
	if s.IsRoot() {
		s.Receipts = make(map[string]*core.OpcodeReceipt)
		s.Receipts["proofs"] = r
	}
	sig, err := bls.Sign(s.suite, s.KP.Private, r.Hash())
	if err != nil {
		return &VerifyProofsResponse{}, err
	}
	sigs := make(map[string]blsproto.BlsSignature)
	sigs["proofs"] = sig
	return &VerifyProofsResponse{Signatures: sigs}, nil
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
