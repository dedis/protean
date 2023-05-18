package verify

import (
	"go.dedis.ch/cothority/v3/blscosi/bdnproto"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"sync"
	"time"

	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3/util/key"

	"github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/sign"
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

	ShufInput  *base.ShuffleInput
	ShufOutput *base.ShuffleOutput

	KP             *key.Pair
	OutputReceipts map[string]*core.OpcodeReceipt

	ShufVerify VerificationFn

	Threshold int
	Success   int
	Failures  int
	Verified  chan bool

	suite     *bn256.Suite
	responses []*VerifyProofsResponse
	mask      *sign.Mask
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewShuffleVerify(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	s := &ShuffleVerify{
		TreeNodeInstance: n,
		Verified:         make(chan bool, 1),
		OutputReceipts:   make(map[string]*core.OpcodeReceipt),
		suite:            bn256.NewSuite(),
		responses:        make([]*VerifyProofsResponse, len(n.Roster().List)),
	}
	err := s.RegisterHandlers(s.verify, s.verifyResponse)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ShuffleVerify) Start() error {
	if len(s.ShufOutput.Proofs) == 0 {
		s.finish(false)
		return xerrors.New("initialize Proofs first")
	}
	err := s.ShufVerify(s.ShufOutput, nil, s.ShufInput.H, s.ShufInput.Pairs,
		s.Roster().Publics())
	if err != nil {
		log.Errorf("%s couldn't verify the proofs: %v", s.Name(), err)
		s.finish(false)
		return err
	}
	resp, err := s.generateResponse()
	if err != nil {
		log.Errorf("%s failed to generate response: %v", s.Name(), err)
		s.finish(false)
		return err
	}
	s.responses[s.Index()] = resp
	s.Success++
	s.mask, err = sign.NewMask(s.suite, s.Roster().ServicePublics(blscosi.ServiceName), s.KP.Public)
	if err != nil {
		log.Errorf("couldn't generate mask: %v", err)
		s.finish(false)
		return err
	}
	vp := &VerifyProofs{
		ShufInput:  s.ShufInput,
		ShufOutput: s.ShufOutput,
	}
	s.timeout = time.AfterFunc(600*time.Second, func() {
		log.Lvl1("Verify protocol timeout")
		s.finish(false)
	})
	errs := s.SendToChildrenInParallel(vp)
	if len(errs) > (len(s.Roster().List) - s.Threshold) {
		log.Errorf("some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (s *ShuffleVerify) verify(r structVerifyProofs) error {
	defer s.Done()
	var err error
	s.ShufInput = r.ShufInput
	s.ShufOutput = r.ShufOutput
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

func (s *ShuffleVerify) verifyResponse(r structVerifyProofsResponse) error {
	index := utils.SearchPublicKey(s.TreeNodeInstance, r.ServerIdentity)
	if len(r.Signatures) == 0 || index < 0 {
		log.Lvl2(r.ServerIdentity, "refused to respond")
		s.Failures++
		if s.Failures > (len(s.Roster().List) - s.Threshold) {
			log.Lvl2(s.ServerIdentity, "couldn't get enough responses")
			s.finish(false)
		}
		return nil
	}

	s.mask.SetBit(index, true)
	s.responses[r.RosterIndex] = &r.VerifyProofsResponse
	s.Success++
	if len(s.responses) == s.Threshold {
		for name, receipt := range s.OutputReceipts {
			var partialSigs [][]byte
			for _, resp := range s.responses {
				if resp != nil {
					partialSigs = append(partialSigs, resp.Signatures[name])
				}
			}
			aggSig, err := bdn.AggregateSignatures(s.suite, partialSigs, s.mask)
			if err != nil {
				log.Error(err)
				s.finish(false)
				return err
			}
			sig, err := aggSig.MarshalBinary()
			if err != nil {
				log.Error(err)
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
	sigs := make(map[string]bdnproto.BdnSignature)
	hash, err := s.ShufOutput.Hash()
	if err != nil {
		return &VerifyProofsResponse{}, err
	}
	r := &core.OpcodeReceipt{
		EPID:      make([]byte, 32),
		OpIdx:     0,
		Name:      "proofs",
		HashBytes: hash,
	}
	if s.IsRoot() {
		s.OutputReceipts["proofs"] = r
	}
	sig, err := bdn.Sign(s.suite, s.KP.Private, r.Hash())
	if err != nil {
		return &VerifyProofsResponse{}, err
	}
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
