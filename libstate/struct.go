package libstate

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
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

type GetContractState struct {
	CID byzcoin.InstanceID
}

type GetContractStateReply struct {
	Proof core.StateProof
}

type ReadState struct {
	CID  byzcoin.InstanceID
	Keys []string
}

type ReadStateReply struct {
	Data      core.ReadState
	Signature protocol.BlsSignature
}

type UpdateState struct {
	CID byzcoin.InstanceID
	Txn byzcoin.ClientTransaction
}

type UpdateStateReply struct {
}
