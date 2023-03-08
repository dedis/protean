package libexec

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	"go.dedis.ch/onet/v3"
)

type InitUnit struct {
	Roster *onet.Roster
}

type InitUnitReply struct{}

type InitTransaction struct {
	Input base.InitTxnInput
}

type InitTransactionReply struct {
	Plan core.ExecutionPlan
}

// Structs for execution request

type Execute struct {
	Input   base.ExecuteInput
	ExecReq core.ExecutionRequest
}

type ExecuteReply struct {
	Output         base.ExecuteOutput
	InputReceipts  map[string]*core.OpcodeReceipt
	OutputReceipts map[string]*core.OpcodeReceipt
}
