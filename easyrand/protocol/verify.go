package protocol

import (
	"go.dedis.ch/cothority/v3/blscosi/bdnproto"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"sync"
	"time"

	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyrand/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3/util/key"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
)

func init() {
	_, err := onet.GlobalProtocolRegister(VerifyProtoName, NewRandomnessVerify)
	if err != nil {
		log.Errorf("cannot register protocol: %v", err)
		panic(err)
	}
}

type RandomnessVerify struct {
	*onet.TreeNodeInstance

	Input       *base.RandomnessInput
	ExecReq     *core.ExecutionRequest
	InputHashes map[string][]byte

	RandOutput *base.RandomnessOutput
	KP         *key.Pair
	Receipts   map[string]*core.OpcodeReceipt

	Threshold int
	Success   int
	Failures  int
	Verified  chan bool

	suite     *bn256.Suite
	responses []*VerifyResponse
	mask      *sign.Mask
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewRandomnessVerify(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	rv := &RandomnessVerify{
		TreeNodeInstance: n,
		Verified:         make(chan bool, 1),
		Receipts:         make(map[string]*core.OpcodeReceipt),
		suite:            bn256.NewSuite(),
		responses:        make([]*VerifyResponse, len(n.Roster().List)),
	}
	err := rv.RegisterHandlers(rv.verifyRandomness, rv.verifyResponse)
	if err != nil {
		return nil, err
	}
	return rv, nil
}

func (rv *RandomnessVerify) Start() error {
	if rv.RandOutput == nil {
		rv.finish(false)
		return xerrors.New("initialize Data first")
	}
	if rv.ExecReq == nil {
		rv.finish(false)
		return xerrors.New("missing execution request")
	}
	err := rv.runVerification()
	if err != nil {
		log.Errorf("%s failed to verify request: %v", rv.Name(), err)
		rv.finish(false)
		return err
	}
	resp, err := rv.generateResponse()
	if err != nil {
		log.Errorf("%s failed to generate response: %v", rv.Name(), err)
		rv.finish(false)
		return err
	}
	rv.responses[rv.Index()] = resp
	rv.Success++
	rv.mask, err = sign.NewMask(rv.suite, rv.Roster().ServicePublics(blscosi.ServiceName),
		rv.KP.Public)
	if err != nil {
		log.Errorf("couldn't generate mask: %v", err)
		rv.finish(false)
		return err
	}
	rv.timeout = time.AfterFunc(5*time.Minute, func() {
		log.Lvl1("RandomnessVerify protocol timeout")
		rv.finish(false)
	})
	errs := rv.SendToChildrenInParallel(&VerifyRand{Input: rv.Input, ExecReq: rv.ExecReq})
	if len(errs) > (len(rv.Roster().List) - rv.Threshold) {
		log.Errorf("some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (rv *RandomnessVerify) verifyRandomness(r structVerifyRand) error {
	defer rv.Done()
	var err error
	rv.Input = r.Input
	rv.ExecReq = r.ExecReq
	rv.InputHashes, err = rv.Input.PrepareHashes()
	if err != nil {
		log.Errorf("%s couldn't prepare input hashes: %v", rv.Name(), err)
		return cothority.ErrorOrNil(rv.SendToParent(&VerifyResponse{}),
			"sending VerifyResponse to parent")
	}
	err = rv.runVerification()
	if err != nil {
		log.Errorf("%s couldn't verify the request: %v", rv.Name(), err)
		return cothority.ErrorOrNil(rv.SendToParent(&VerifyResponse{}),
			"sending VerifyResponse to parent")
	}
	resp, err := rv.generateResponse()
	if err != nil {
		log.Errorf("%s couldn't generate response: %v", rv.Name(), err)
	}
	return cothority.ErrorOrNil(rv.SendToParent(resp),
		"sending VerifyResponse to parent")
}

func (rv *RandomnessVerify) verifyResponse(r structVerifyResponse) error {
	index := utils.SearchPublicKey(rv.TreeNodeInstance, r.ServerIdentity)
	if len(r.Signatures) == 0 || index < 0 {
		log.Lvl2(r.ServerIdentity, "refused to respond")
		rv.Failures++
		if rv.Failures > (len(rv.Roster().List) - rv.Threshold) {
			log.Lvl2(rv.ServerIdentity, "couldn't get enough responses")
			rv.finish(false)
		}
		return nil
	}

	rv.mask.SetBit(index, true)
	rv.responses[r.RosterIndex] = &r.VerifyResponse
	rv.Success++
	if rv.Success == rv.Threshold {
		for name, receipt := range rv.Receipts {
			var partialSigs [][]byte
			for _, resp := range rv.responses {
				if resp != nil {
					partialSigs = append(partialSigs, resp.Signatures[name])
				}
			}
			aggSig, err := bdn.AggregateSignatures(rv.suite, partialSigs, rv.mask)
			if err != nil {
				log.Error(err)
				rv.finish(false)
				return err
			}
			sig, err := aggSig.MarshalBinary()
			if err != nil {
				log.Error(err)
				rv.finish(false)
				return err
			}
			receipt.Sig = append(sig, rv.mask.Mask()...)
		}
		rv.finish(true)
	}
	return nil
}

func (rv *RandomnessVerify) generateResponse() (*VerifyResponse, error) {
	hash, err := rv.RandOutput.Hash()
	if err != nil {
		return &VerifyResponse{}, err
	}
	r := &core.OpcodeReceipt{
		EPID:      rv.ExecReq.EP.Hash(),
		OpIdx:     rv.ExecReq.Index,
		Name:      "randomness",
		HashBytes: hash,
	}
	if rv.IsRoot() {
		rv.Receipts["randomness"] = r
	}
	sig, err := bdn.Sign(rv.suite, rv.KP.Private, r.Hash())
	if err != nil {
		return &VerifyResponse{}, err
	}
	sigs := make(map[string]bdnproto.BdnSignature)
	sigs["randomness"] = sig
	return &VerifyResponse{Signatures: sigs}, nil
}

func (rv *RandomnessVerify) runVerification() error {
	vData := &core.VerificationData{
		UID:         base.UID,
		OpcodeName:  base.GET_RAND,
		InputHashes: rv.InputHashes,
	}
	return rv.ExecReq.Verify(vData)
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
