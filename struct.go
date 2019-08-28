package protean

import (
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
)

type ScInitData struct {
	MHeight int
	BHeight int
}

type UnitInfo struct {
	UnitID   string
	UnitName string
	Txns     map[string]string
}

type BaseStorage struct {
	UInfo    *UnitInfo
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
	Workflow []*WfNode
	Publics  map[string]*Identity
}

type ExecutionData struct {
	Index    int
	ExecPlan *ExecutionPlan
	PlanSig  protocol.BlsSignature
	SigMap   map[int]protocol.BlsSignature
}
