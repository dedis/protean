package protocol

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/dedis/protean/core"
	"go.dedis.ch/kyber/v3/util/key"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
)

func init() {
	_, err := onet.GlobalProtocolRegister(VerifyProtoName, NewVerify)
	if err != nil {
		log.Errorf("cannot register protocol: %v", err)
		panic(err)
	}
}

type Verify struct {
	*onet.TreeNodeInstance

	InputData   map[string][]byte
	InputHashes map[string][]byte
	StateProofs map[string]*core.StateProof
	ExecReq     *core.ExecutionRequest
	KP          *key.Pair

	Threshold int
	Failures  int
	Verified  chan bool

	responses []*VerifyResponse
	suite     *pairing.SuiteBn256
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewVerify(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	v := &Verify{
		TreeNodeInstance: n,
		Verified:         make(chan bool, 1),
		InputHashes:      make(map[string][]byte),
		suite:            pairing.NewSuiteBn256(),
	}
	err := v.RegisterHandlers(v.verify, v.verifyResponse)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Verify) Start() error {
	if v.ExecReq == nil {
		v.finish(false)
		return xerrors.New("missing execution request")
	}
	if len(v.StateProofs) > 0 {
		_, err := core.PrepareKVDicts(v.ExecReq, v.StateProofs)
		if err != nil {
			log.Errorf("%s failed to prepare kv dicts: %v", v.Name(), err)
			v.finish(false)
			return err
		}
	}
	if len(v.InputData) > 0 {
		v.prepareInputHashes()
	}
	err := v.runVerification()
	if err != nil {
		log.Errorf("%s failed to verify request: %v", v.Name(), err)
		v.finish(false)
		return err
	}
	v.timeout = time.AfterFunc(5*time.Minute, func() {
		log.Lvl1("Verify protocol timeout")
		v.finish(false)
	})
	errs := v.SendToChildrenInParallel(&VerifyRequest{InputData: v.InputData,
		StateProofs: v.StateProofs, ExecReq: v.ExecReq})
	if len(errs) > (len(v.Roster().List) - v.Threshold) {
		log.Errorf("some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (v *Verify) verify(r structVerify) error {
	defer v.Done()
	var err error
	v.InputData = r.InputData
	v.StateProofs = r.StateProofs
	v.ExecReq = r.ExecReq
	if len(v.StateProofs) > 0 {
		_, err := core.PrepareKVDicts(v.ExecReq, v.StateProofs)
		if err != nil {
			log.Errorf("%s failed to prepare kv dicts: %v", v.Name(), err)
			return cothority.ErrorOrNil(v.SendToParent(
				&VerifyResponse{Success: false}), "sending VerifyResponse to parent")
		}
	}
	if len(v.InputData) > 0 {
		v.prepareInputHashes()
	}
	err = v.runVerification()
	if err != nil {
		log.Errorf("%s couldn't verify the request: %v", v.Name(), err)
		return cothority.ErrorOrNil(v.SendToParent(
			&VerifyResponse{Success: false}), "sending VerifyResponse to parent")
	}
	return cothority.ErrorOrNil(v.SendToParent(&VerifyResponse{Success: true}),
		"sending VerifyResponse to parent")
}

func (v *Verify) verifyResponse(r structVerifyResponse) error {
	if !r.Success {
		log.Lvl2(r.ServerIdentity, "failed to verify")
		v.Failures++
		if v.Failures > (len(v.Roster().List) - v.Threshold) {
			log.Lvl2(v.ServerIdentity, "couldn't get enough responses")
			v.finish(false)
		}
		return nil
	}
	v.responses = append(v.responses, &r.VerifyResponse)
	if len(v.responses) >= v.Threshold-1 {
		v.finish(true)
	}
	return nil
}

func (v *Verify) prepareInputHashes() {
	for varName, data := range v.InputData {
		h := sha256.New()
		h.Write(data)
		v.InputHashes[varName] = h.Sum(nil)
	}
}

func (v *Verify) runVerification() error {
	vData := &core.VerificationData{
		UID:         "verifier",
		OpcodeName:  "verify",
		InputHashes: v.InputHashes,
		StateProofs: v.StateProofs,
	}
	return v.ExecReq.Verify(vData)
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
