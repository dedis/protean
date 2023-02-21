package verify

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libstate/base"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

func init() {
	_, err := onet.GlobalProtocolRegister(ProtoName, NewUpdateVerify)
	if err != nil {
		log.Errorf("cannot register protocol: %v", err)
		panic(err)
	}
}

type Verify struct {
	*onet.TreeNodeInstance

	Input       *base.UpdateInput
	ExecReq     *core.ExecutionRequest
	InputHashes map[string][]byte
	Receipts    map[string]*core.OpcodeReceipt

	VerifyFn  base.VerifyFn
	Threshold int
	Failures  int
	Verified  chan bool

	suite     *pairing.SuiteBn256
	responses []*Response
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewUpdateVerify(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	v := &Verify{
		TreeNodeInstance: n,
		Verified:         make(chan bool, 1),
		suite:            pairing.NewSuiteBn256(),
	}
	err := v.RegisterHandlers(v.verifyRequest, v.verifyResponse)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Verify) Start() error {
	if v.Input == nil {
		v.finish(false)
		return xerrors.New("missing input")
	}
	if v.ExecReq == nil {
		v.finish(false)
		return xerrors.New("missing execution request")
	}
	err := v.ExecReq.Verify(&core.VerificationData{UID: base.UID,
		OpcodeName: base.UPDATE_STATE, InputHashes: v.InputHashes})
	if err != nil {
		log.Errorf("couldn't verify the execution request: %v", err)
		v.finish(false)
		return err
	}
	verified := v.VerifyFn(v.Input, v.ExecReq)
	if !verified {
		v.finish(false)
		return xerrors.New("could not verify update state")
	}
	v.timeout = time.AfterFunc(2*time.Minute, func() {
		log.Lvl1("verify protocol timeout")
		v.finish(false)
	})
	errs := v.Broadcast(&Request{Input: v.Input, ExecReq: v.ExecReq})
	if len(errs) > (len(v.Roster().List) - v.Threshold) {
		log.Errorf("some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (v *Verify) verifyRequest(r structRequest) error {
	defer v.Done()
	resp := Response{}
	v.InputHashes = r.Input.PrepareInputHashes()
	err := r.ExecReq.Verify(&core.VerificationData{UID: base.UID,
		OpcodeName: base.UPDATE_STATE, InputHashes: v.InputHashes})
	if err != nil {
		log.Errorf("%s could not verify the execution request: %v", v.Name(), err)
		resp.Verified = false
		return cothority.ErrorOrNil(v.SendToParent(&resp),
			"sending Response to parent")
	}
	resp.Verified = v.VerifyFn(r.Input, r.ExecReq)
	if !resp.Verified {
		log.Errorf("%s could not verify update request", v.Name())
	}
	return cothority.ErrorOrNil(v.SendToParent(&resp),
		"sending Response to parent")
}

func (v *Verify) verifyResponse(r structResponse) error {
	if !r.Verified {
		log.Lvl2(r.ServerIdentity, "couldn't verify the request")
		v.Failures++
		if v.Failures > (len(v.Roster().List) - v.Threshold) {
			log.Lvl2(v.ServerIdentity, "couldn't get enough responses")
			v.finish(false)
		}
	}
	v.responses = append(v.responses, &r.Response)
	if len(v.responses) >= v.Threshold-1 {
		v.finish(true)
	}
	return nil
}

func (v *Verify) finish(result bool) {
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
