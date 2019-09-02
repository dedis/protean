package compiler

import (
	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

type InitUnitRequest struct {
	Roster *onet.Roster
	ScCfg  *sys.ScConfig
}

type InitUnitReply struct {
	Genesis skipchain.SkipBlockID
}

type CreateUnitsRequest struct {
	Units []*sys.FunctionalUnit
}

type CreateUnitsReply struct{}

type ExecutionPlanRequest struct {
	Workflow *sys.Workflow
	SigMap   map[string][]byte
}

type ExecutionPlanReply struct {
	ExecPlan  *sys.ExecutionPlan
	Signature protocol.BlsSignature
}

type DirectoryInfoRequest struct{}

type DirectoryInfoReply struct {
	Directory map[string]*sys.UnitInfo
}

type StoreGenesisRequest struct {
	Genesis []byte
}

type StoreGenesisReply struct{}

type verifyEpData struct {
	Root string
	Ep   *sys.ExecutionPlan
	Sm   map[string][]byte
}

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
