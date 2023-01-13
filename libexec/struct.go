package libexec

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
)

type InitUnitRequest struct {
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
	Plan      core.ExecutionPlan
	Signature protocol.BlsSignature
}
