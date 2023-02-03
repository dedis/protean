package easyrand

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyrand/base"
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&InitDKGRequest{}, &InitDKGReply{}, &RandomnessRequest{},
		&RandomnessReply{})
}

type InitUnitRequest struct {
	Roster *onet.Roster
}

type InitUnitReply struct{}

type InitDKGRequest struct{}

// InitDKGReply is the response of DKG.
type InitDKGReply struct {
	Public kyber.Point
}

// RandomnessRequest is a request to get the public randomness.
type RandomnessRequest struct {
	Input   base.RandomnessInput
	ExecReq core.ExecutionRequest
}

// RandomnessReply is the returned public randomness.
type RandomnessReply struct {
	Public kyber.Point
	Round  uint64
	Prev   []byte
	// Value is the collective signature. Use the hash of it!
	Value     []byte
	Signature blscosi.BlsSignature
}
