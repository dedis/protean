package compiler

import (
	"github.com/ceyhunalp/protean_code"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

type FunctionalUnit struct {
	UnitType  int
	UnitName  string
	Roster    *onet.Roster
	Publics   []kyber.Point
	NumNodes  int
	NumFaulty int
	Txns      []string
	//Txns       []*Transaction
}

type Identity struct {
	Keys []kyber.Point
}

type ExecutionPlan struct {
	//TODO: Get this out of here. It is a temporary hack - or is it?
	Genesis  []byte
	Workflow []*protean.WfNode
	Publics  map[string]*Identity
	//Publics  map[string][]kyber.Point
}

type UnitData struct {
	UnitID   string
	UnitName string
	Txns     map[string]string
}

//type CreateSkipchainRequest struct {
//Roster  *onet.Roster
//MHeight int
//BHeight int
//}

//type CreateSkipchainReply struct {
//Genesis []byte
//Sb      *skipchain.SkipBlock
//}

type CreateUnitsRequest struct {
	Genesis []byte
	Units   []*FunctionalUnit
}

type CreateUnitsReply struct {
	Data []*UnitData
	//SbID skipchain.SkipBlockID
}

type ExecutionPlanRequest struct {
	Genesis  []byte
	Workflow []*protean.WfNode
}

type ExecutionPlanReply struct {
	ExecPlan  *ExecutionPlan
	Signature protocol.BlsSignature
}

type LogSkipchainRequest struct {
	Genesis []byte
}

type LogSkipchainReply struct {
}

type sbData struct {
	Data map[string]*uv
}

type uv struct {
	R  *onet.Roster
	Ps []kyber.Point
	Nn int
	Nf int
	// Set of transaction IDs
	//Txn ID -> Txn name
	Txns map[string]string
}

type edge struct {
	parent  int
	child   int
	removed bool
}

//type csConfig struct {
//Roster  *onet.Roster
//Genesis []byte
//}
