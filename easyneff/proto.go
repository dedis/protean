package easyneff

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/easyneff/protocol"
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&ShuffleRequest{}, &ShuffleReply{})
}

type InitUnitRequest struct {
	Roster *onet.Roster
}

type InitUnitReply struct{}

type ShuffleRequest struct {
	Input   base.ShuffleInput
	ExecReq core.ExecutionRequest
}

// ShuffleReply is the result of all the proofs of the shuffle. The client is
// responsible for verifying the result.
type ShuffleReply struct {
	Proofs    []protocol.Proof
	Signature blscosi.BlsSignature
}
