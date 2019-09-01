package sys

import (
	"time"

	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

type UnitConfig struct {
	Roster       *onet.Roster
	ScCfg        *ScConfig
	BaseStore    *BaseStorage
	BlkInterval  time.Duration
	DurationType time.Duration
}

type ScConfig struct {
	MHeight int
	BHeight int
}

type UnitJSON struct {
	Type     int      `json:"type"`
	Name     string   `json:"name"`
	NumNodes int      `json:"numnodes"`
	Txns     []string `json:"txns"`
}

type WfJSON struct {
	Index    int    `json:"index"`
	UnitName string `json:"uname"`
	TxnName  string `json:"tname"`
	Deps     []int  `json:"deps"`
}

type FunctionalUnit struct {
	Type     int
	Name     string
	NumNodes int
	Txns     []string
	Roster   *onet.Roster
	Publics  []kyber.Point
}

type WfNode struct {
	UID  string
	TID  string
	Deps []int
}

type Workflow struct {
	Nodes []*WfNode
	// AuthPublics stores the public keys of the users who can execute this
	// workflow. Keys are the public keys in string format.
	AuthPublics map[string]kyber.Point
	// If true, this workflow can only be executed if all the authenticated
	// users provide a signature
	All bool
}

type UnitInfo struct {
	UnitID   string
	UnitName string
	Txns     map[string]string
}

type BaseStorage struct {
	UInfo       *UnitInfo
	CompPublics []kyber.Point
}

type UnitIdentity struct {
	Keys []kyber.Point
}

type ExecutionPlan struct {
	Workflow *Workflow
	Publics  map[string]*UnitIdentity
}

type ExecutionData struct {
	Index    int
	ExecPlan *ExecutionPlan
	PlanSig  protocol.BlsSignature
	SigMap   map[int]protocol.BlsSignature
}

type SerializedWf struct {
	Nodes       []*WfNode
	AuthPublics []byte
	All         bool
}

type SerializedEp struct {
	//Nodes       []*WfNode
	//AuthPublics []byte
	//All         bool
	Swf     *SerializedWf
	Publics []byte
}
