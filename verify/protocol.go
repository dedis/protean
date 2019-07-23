package verify

import (
	"fmt"
	"sync"
	"time"

	"github.com/ceyhunalp/protean_code"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(&Verify{}, &VerifyReply{})
	_, err := onet.GlobalProtocolRegister(Name, NewVerifyExecutionPlan)
	if err != nil {
		log.Errorf("Cannot register protocol: %v", err)
	}
}

type VP struct {
	*onet.TreeNodeInstance
	Index          int
	Block          *skipchain.SkipBlock
	ExecPlan       *protean.ExecutionPlan
	PlanSig        protocol.BlsSignature
	SigMap         map[int]protocol.BlsSignature
	FaultThreshold int
	Failures       int
	Verified       chan bool
	replies        []VerifyReply
	timeout        *time.Timer
	doneOnce       sync.Once
}

// Check that *TemplateProtocol implements onet.ProtocolInstance
//var _ onet.ProtocolInstance = (*TemplateProtocol)(nil)
var _ onet.ProtocolInstance = (*VP)(nil)

// NewProtocol initialises the structure for use in one round
func NewVerifyExecutionPlan(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	vp := &VP{
		TreeNodeInstance: n,
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
	if vp.SigMap == nil {
		vp.finish(false)
		return fmt.Errorf("Signature map is missing")
	}

	v := &Verify{
		Index:   vp.Index,
		Plan:    vp.ExecPlan,
		Block:   vp.Block,
		PlanSig: vp.PlanSig,
		SigMap:  vp.SigMap,
	}

	if !verifyPlan(v) {
		vp.finish(false)
		return fmt.Errorf("Verification failed")
	}

	//TODO: Do what the children will do here - i.e. sigver

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
	if !verifyPlan(&sv.Verify) {
		log.Errorf("Verify plan failed at: %s", vp.ServerIdentity())
		return vp.SendToParent(&VerifyReply{
			Success: false,
		})
	}
	return vp.SendToParent(&VerifyReply{
		Success: true,
	})
}

func (vp *VP) verifyExecPlanReply(vr ProtoVerifyReply) error {
	if vr.Success == false {
		log.Lvl2("Node", vr.ServerIdentity, "failed verificiation")
		vp.Failures++
		if vp.Failures > len(vp.Roster().List)-vp.FaultThreshold {
			log.Lvl2(vr.ServerIdentity, "could not get enough success messages")
			vp.finish(false)
		}
		return nil
	}

	vp.replies = append(vp.replies, vr.VerifyReply)
	// Excluding the root
	if len(vp.replies) >= int(vp.FaultThreshold-1) {
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
