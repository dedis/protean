package easyrand

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyrand/base"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&InitDKGRequest{}, &InitDKGReply{}, &CreateRandomnessRequest{},
		&CreateRandomnessReply{}, &GetRandomnessRequest{}, &GetRandomnessReply{})
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

// CreateRandomnessRequest is a request to get the public randomness.
type CreateRandomnessRequest struct{}

// CreateRandomnessReply is the returned public randomness.
type CreateRandomnessReply struct{}

type GetRandomnessRequest struct {
	Input   base.RandomnessInput
	ExecReq core.ExecutionRequest
}

type GetRandomnessReply struct {
	Output   base.RandomnessOutput
	Receipts map[string]*core.OpcodeReceipt
}
