package compiler

import (
	"github.com/dedis/protean"
	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

//type FunctionalUnit struct {
//UnitType  int
//UnitName  string
//Roster    *onet.Roster
//Publics   []kyber.Point
//NumNodes  int
//NumFaulty int
//Txns      []string
////Txns       []*Transaction
//}

type InitUnitRequest struct {
	Roster *onet.Roster
	ScData *protean.ScInitData
}

type InitUnitReply struct {
	Genesis skipchain.SkipBlockID
}

type CreateUnitsRequest struct {
	Units []*sys.FunctionalUnit
}

type CreateUnitsReply struct{}

type ExecutionPlanRequest struct {
	Workflow []*protean.WfNode
}

type ExecutionPlanReply struct {
	ExecPlan  *protean.ExecutionPlan
	Signature protocol.BlsSignature
}

type DirectoryDataRequest struct{}

type DirectoryDataReply struct {
	Data []*protean.UnitInfo
}

type StoreGenesisRequest struct {
	Genesis []byte
}

type StoreGenesisReply struct{}

type sbData struct {
	Data map[string]*uv
}

type uv struct {
	N  string
	R  *onet.Roster
	Ps []kyber.Point
	// Set of transaction IDs
	//Txn ID -> Txn name
	Txns map[string]string
}

type edge struct {
	parent  int
	child   int
	removed bool
}
