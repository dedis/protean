package compiler

import (
	protean "github.com/ceyhunalp/protean_code"
	"github.com/ceyhunalp/protean_code/utils"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
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

//type UnitInformation struct {
//UnitID   string
//UnitName string
//Txns     map[string]string
//}

type InitUnitRequest struct {
	ScData *utils.ScInitData
}

type InitUnitReply struct {
	Genesis []byte
	//Sb      *skipchain.SkipBlock
}

type CreateUnitsRequest struct {
	Genesis []byte
	Units   []*FunctionalUnit
}

type CreateUnitsReply struct {
	UnitDirectory []*protean.UnitInfo
	SbID          skipchain.SkipBlockID
}

type ExecutionPlanRequest struct {
	Genesis  []byte
	Workflow []*protean.WfNode
}

type ExecutionPlanReply struct {
	ExecPlan  *protean.ExecutionPlan
	Signature protocol.BlsSignature
}

type LogSkipchainRequest struct {
	Genesis []byte
}

type LogSkipchainReply struct {
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
