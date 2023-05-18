package bdn

import (
	"crypto/sha256"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/blscosi/bdnproto"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"sync"
	"time"

	"github.com/dedis/protean/core"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/kyber/v3/util/key"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
)

func init() {
	_, err := onet.GlobalProtocolRegister(BDNSignProtoName, NewBDNSign)
	if err != nil {
		log.Errorf("cannot register protocol: %v", err)
		panic(err)
	}
}

type BDNSign struct {
	*onet.TreeNodeInstance

	OutputData map[string][]byte
	ExecReq    *core.ExecutionRequest
	KP         *key.Pair
	Receipts   map[string]*core.OpcodeReceipt

	Threshold int
	Success   int
	Failures  int
	Signed    chan bool

	suite *bn256.Suite

	responses []*BDNSignResponse
	mask      *sign.Mask
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewBDNSign(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	rv := &BDNSign{
		TreeNodeInstance: n,
		Signed:           make(chan bool, 1),
		Receipts:         make(map[string]*core.OpcodeReceipt),
		suite:            bn256.NewSuite(),
		responses:        make([]*BDNSignResponse, len(n.Roster().List)),
	}
	err := rv.RegisterHandlers(rv.sign, rv.signResponse)
	if err != nil {
		return nil, err
	}
	return rv, nil
}

func (s *BDNSign) Start() error {
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
	s.responses[s.Index()] = resp
	s.Success++
	s.mask, err = sign.NewMask(s.suite, s.Roster().ServicePublics(blscosi.ServiceName),
		s.KP.Public)
	if err != nil {
		log.Errorf("couldn't generate mask: %s", err)
		s.finish(false)
		return err
	}
	s.timeout = time.AfterFunc(5*time.Minute, func() {
		log.Lvl1("BDNSign protocol timeout")
		s.finish(false)
	})
	errs := s.SendToChildrenInParallel(&BDNSignRequest{OutputData: s.
		OutputData, ExecReq: s.ExecReq})
	if len(errs) > (len(s.Roster().List) - s.Threshold) {
		log.Errorf("some nodes failed with error(s) %s", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (s *BDNSign) sign(r structBDNSign) error {
	defer s.Done()
	var err error
	s.ExecReq = r.ExecReq
	s.OutputData = r.OutputData
	resp, err := s.generateResponse()
	if err != nil {
		log.Errorf("%s couldn't generate response: %s", s.Name(), err)
	}
	return cothority.ErrorOrNil(s.SendToParent(resp),
		"sending BDNSignResponse to parent")
}

func (s *BDNSign) signResponse(r structBDNSignResponse) error {
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
	err := s.mask.SetBit(index, true)
	if err != nil {
		log.Error(err)
		return err
	}
	s.Success++
	s.responses[r.RosterIndex] = &r.BDNSignResponse
	if s.Success == s.Threshold {
		for name, receipt := range s.Receipts {
			var partialSigs [][]byte
			for _, resp := range s.responses {
				if resp != nil {
					partialSigs = append(partialSigs, resp.Signatures[name])
				}
			}
			aggSig, err := bdn.AggregateSignatures(s.suite,
				partialSigs, s.mask)
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

func (s *BDNSign) generateResponse() (*BDNSignResponse, error) {
	sigs := make(map[string]bdnproto.BdnSignature)
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
		sig, err := bdn.Sign(s.suite, s.KP.Private, r.Hash())
		if err != nil {
			return &BDNSignResponse{}, err
		}
		sigs[varName] = sig
	}
	return &BDNSignResponse{Signatures: sigs}, nil
}

func (s *BDNSign) finish(result bool) {
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
