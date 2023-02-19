package libstate

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libstate/base"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
)

type Request struct {
	Data interface{}
}

type InitUnitRequest struct {
	ByzID  skipchain.SkipBlockID
	Roster *onet.Roster
}

type InitUnitReply struct{}

type InitContractReply struct {
	CID    byzcoin.InstanceID
	TxResp *byzcoin.AddTxResponse
}

type GetStateRequest struct {
	CID byzcoin.InstanceID
}

type GetStateReply struct {
	Proof core.StateProof
}

type UpdateStateRequest struct {
	Input   base.UpdateInput
	ExecReq core.ExecutionRequest
	Wait    int
}

type UpdateStateReply struct {
	TxResp *byzcoin.AddTxResponse
	//Receipts map[string]*core.OpcodeReceipt
}
