package libstate

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libstate/base"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
)

type Request struct {
	Data interface{}
}

type InitUnitRequest struct {
	ByzID  skipchain.SkipBlockID
	Roster *onet.Roster
	Darc   *darc.Darc
	Signer darc.Signer
}

type InitUnitReply struct{}

type InitContractRequest struct {
	Raw      *core.ContractRaw
	Header   *core.ContractHeader
	InitArgs byzcoin.Arguments
	Wait     int
}

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
	Input         base.UpdateInput
	ExecReq       core.ExecutionRequest
	Wait          int
	InputReceipts map[int]map[string]*core.OpcodeReceipt
}

type UpdateStateReply struct {
	TxResp *byzcoin.AddTxResponse
}

type DummyRequest struct {
	CID   byzcoin.InstanceID
	Input base.UpdateInput
	Wait  int
}

type DummyReply struct {
	TxResp *byzcoin.AddTxResponse
}
