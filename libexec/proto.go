package libexec

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
)

type InitUnit struct {
	Roster *onet.Roster
}

type InitUnitReply struct{}

type ByzData struct {
	IID     byzcoin.InstanceID
	Proof   byzcoin.Proof
	Genesis skipchain.SkipBlock
}

type InitTransaction struct {
	RData   ByzData
	CData   ByzData
	WfName  string
	TxnName string
}

type InitTransactionReply struct {
	Plan core.ExecutionPlan
}

// Structs for execution request

type Execute struct {
	FnName  string
	Input   base.ExecuteInput
	ExecReq core.ExecutionRequest
}

type ExecuteReply struct {
	Output   base.ExecuteOutput
	Receipts map[string]*core.OpcodeReceipt
}
