package verify

import (
	"fmt"
	"sync"
	"time"

	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(&Verify{}, &VerifyReply{})
	_, err := onet.GlobalProtocolRegister(Name, NewVerifyExecutionRequest)
	if err != nil {
		log.Errorf("Cannot register protocol: %v", err)
	}
}

type VP struct {
	*onet.TreeNodeInstance
	Index       int
	TxnName     string
	Block       *skipchain.SkipBlock
	ExecPlan    *sys.ExecutionPlan
	ClientSigs  map[string][]byte
	CompilerSig protocol.BlsSignature
	UnitSigs    []protocol.BlsSignature

	Threshold      int
	FaultThreshold int
	Failures       int
	Verified       chan bool
	replies        []VerifyReply
	timeout        *time.Timer
	doneOnce       sync.Once
}

var _ onet.ProtocolInstance = (*VP)(nil)

func NewVerifyExecutionRequest(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	numNodes := len(n.Roster().List)
	vp := &VP{
		TreeNodeInstance: n,
		Threshold:        numNodes - (numNodes-1)/3,
		FaultThreshold:   (numNodes - 1) / 3,
		Verified:         make(chan bool, 1),
	}
	for _, handler := range []interface{}{vp.verifyExecPlan, vp.verifyExecPlanReply} {
		if err := vp.RegisterHandler(handler); err != nil {
			log.Errorf("Cannot register handler %s: %v", handler, err)
			return nil, err
		}
	}
	return vp, nil
}

func (vp *VP) Start() error {
	log.Lvl3("Starting protocol")
	if vp.ExecPlan == nil {
		vp.finish(false)
		return fmt.Errorf("Execution plan missing")
	}
	if vp.Block == nil {
		vp.finish(false)
		return fmt.Errorf("Block missing")
	}
	if vp.UnitSigs == nil {
		vp.finish(false)
		return fmt.Errorf("Signature map is missing")
	}
	v := &Verify{
		Index:       vp.Index,
		TxnName:     vp.TxnName,
		Block:       vp.Block,
		ExecPlan:    vp.ExecPlan,
		ClientSigs:  vp.ClientSigs,
		CompilerSig: vp.CompilerSig,
		UnitSigs:    vp.UnitSigs,
	}

	vp.timeout = time.AfterFunc(1*time.Minute, func() {
		log.Lvl1("VerifyPlan protocol timeout")
		vp.finish(false)
	})
	errs := vp.Broadcast(v)
	if len(errs) > vp.FaultThreshold {
		log.Errorf("Some nodes failed with error(s): %v", errs)
		return fmt.Errorf("Too many nodes failed in broadcast")
	}
	return nil
}

func (vp *VP) verifyExecPlan(sv ProtoVerify) error {
	log.Lvl2(vp.Name() + ": starting verification")
	defer vp.Done()
	success := verifyPlan(&sv.Verify)
	if !success {
		log.Errorf("Verify plan failed at: %s", vp.ServerIdentity())
	}
	return vp.SendToParent(&VerifyReply{Success: success})
}

func (vp *VP) verifyExecPlanReply(vr ProtoVerifyReply) error {
	log.LLvlf2("%s is the root node", vp.ServerIdentity())
	if vr.Success == false {
		log.Lvl2("Node", vr.ServerIdentity, "failed verificiation")
		vp.Failures++
		if vp.Failures > vp.FaultThreshold {
			log.Lvl2(vr.ServerIdentity, "could not get enough success messages")
			vp.finish(false)
		}
		return nil
	}

	vp.replies = append(vp.replies, vr.VerifyReply)
	// Excluding the root
	if len(vp.replies) >= int(vp.Threshold-1) {
		log.Lvl2("Received", len(vp.replies)+1, "success messages. Verification success")
		vp.finish(true)
	}
	return nil
}

func (vp *VP) finish(result bool) {
	vp.timeout.Stop()
	select {
	case vp.Verified <- result:
	default:
	}
	vp.doneOnce.Do(func() { vp.Done() })
}
