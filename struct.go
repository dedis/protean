package protean

import (
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
)

type UnitStorage struct {
	UnitID   string
	Txns     map[string]string
	CompKeys []kyber.Point
}

type WfNode struct {
	UID  string
	TID  string
	Deps []int
}

type Identity struct {
	Keys []kyber.Point
}

type ExecutionPlan struct {
	//TODO: Get this out of here. It is a temporary hack - or is it?
	Genesis  []byte
	Workflow []*WfNode
	Publics  map[string]*Identity
}

type ExecutionData struct {
	Index    int
	ExecPlan *ExecutionPlan
	PlanSig  protocol.BlsSignature
	SigMap   map[int]protocol.BlsSignature
}
