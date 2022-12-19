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

type InitRequest struct {
	ByzID  skipchain.SkipBlockID
	Roster *onet.Roster
}

type InitUnitReply struct{}

type InitContract struct {
	CID    byzcoin.InstanceID
	TxResp *byzcoin.AddTxResponse
}

type GetState struct {
	CID byzcoin.InstanceID
}

type GetStateReply struct {
	Proof core.StateProof
	//Signature protocol.BlsSignature
}

type ReadState struct {
	CID  byzcoin.InstanceID
	Keys []string
}

type ReadStateReply struct {
	Data      core.ReadState
	Signature protocol.BlsSignature
}
