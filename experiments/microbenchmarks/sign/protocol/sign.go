package protocol

import (
	"crypto/sha256"
	blsproto "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3/sign/bls"
	"sync"
	"time"

	"github.com/dedis/protean/core"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3/util/key"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
)

func init() {
	_, err := onet.GlobalProtocolRegister(SignProtoName, NewSign)
	if err != nil {
		log.Errorf("cannot register protocol: %v", err)
		panic(err)
	}
}

type Sign struct {
	*onet.TreeNodeInstance

	OutputData map[string][]byte
	ExecReq    *core.ExecutionRequest
	KP         *key.Pair
	Receipts   map[string]*core.OpcodeReceipt

	Threshold int
	Failures  int
	Signed    chan bool

	suite     *pairing.SuiteBn256
	responses []*SignResponse
	mask      *sign.Mask
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewSign(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	rv := &Sign{
		TreeNodeInstance: n,
		Signed:           make(chan bool, 1),
		Receipts:         make(map[string]*core.OpcodeReceipt),
		suite:            pairing.NewSuiteBn256(),
	}
	err := rv.RegisterHandlers(rv.sign, rv.signResponse)
	if err != nil {
		return nil, err
	}
	return rv, nil
}

func (s *Sign) Start() error {
	if s.OutputData == nil {
		s.finish(false)
		return xerrors.New("initialize OutputData first")
	}
	if s.ExecReq == nil {
		s.finish(false)
		return xerrors.New("missing execution request")
	}
	resp, err := s.generateResponse()
	if err != nil {
		log.Errorf("%s failed to generate response: %s", s.Name(), err)
		s.finish(false)
		return err
	}
	s.responses = append(s.responses, resp)
	s.mask, err = sign.NewMask(s.suite, s.Roster().ServicePublics(blscosi.ServiceName),
		s.KP.Public)
	if err != nil {
		log.Errorf("couldn't generate mask: %s", err)
		s.finish(false)
		return err
	}
	s.timeout = time.AfterFunc(5*time.Minute, func() {
		log.Lvl1("Sign protocol timeout")
		s.finish(false)
	})
	errs := s.SendToChildrenInParallel(&SignRequest{OutputData: s.OutputData, ExecReq: s.ExecReq})
	if len(errs) > (len(s.Roster().List) - s.Threshold) {
		log.Errorf("some nodes failed with error(s) %s", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (s *Sign) sign(r structSign) error {
	defer s.Done()
	var err error
	s.ExecReq = r.ExecReq
	s.OutputData = r.OutputData
	resp, err := s.generateResponse()
	if err != nil {
		log.Errorf("%s couldn't generate response: %s", s.Name(), err)
	}
	return cothority.ErrorOrNil(s.SendToParent(resp),
		"sending SignResponse to parent")
}

func (s *Sign) signResponse(r structSignResponse) error {
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
	s.responses = append(s.responses, &r.SignResponse)
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

func (s *Sign) generateResponse() (*SignResponse, error) {
	sigs := make(map[string]blsproto.BlsSignature)
	for varName, data := range s.OutputData {
		h := sha256.New()
		h.Write(data)
		dataHash := h.Sum(nil)
		r := core.OpcodeReceipt{
			EPID:      s.ExecReq.EP.Hash(),
			OpIdx:     s.ExecReq.Index,
			Name:      varName,
			HashBytes: dataHash,
		}
		if s.IsRoot() {
			s.Receipts[varName] = &r
		}
		sig, err := bls.Sign(s.suite, s.KP.Private, r.Hash())
		if err != nil {
			return &SignResponse{}, err
		}
		sigs[varName] = sig
	}
	return &SignResponse{Signatures: sigs}, nil
}

func (s *Sign) finish(result bool) {
	s.timeout.Stop()
	select {
	case s.Signed <- result:
		// succeeded
	default:
		// would have blocked because some other call to finish()
		// beat us.
	}
	s.doneOnce.Do(func() { s.Done() })
}
