package threshold

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/threshold/base"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&InitDKGRequest{}, &InitDKGReply{}, &DecryptRequest{},
		&DecryptReply{})
}

type InitUnitRequest struct {
	Roster *onet.Roster
}

type InitUnitReply struct{}

type InitDKGRequest struct {
	ExecReq core.ExecutionRequest
}

type InitDKGReply struct {
	X        kyber.Point
	Receipts map[string]*core.OpcodeReceipt
}

type DecryptRequest struct {
	Input   base.DecryptInput
	ExecReq core.ExecutionRequest
}

type DecryptReply struct {
	Ps       []kyber.Point
	Receipts map[string]*core.OpcodeReceipt
}

// Internal structs

type pubPoly struct {
	B       kyber.Point
	Commits []kyber.Point
}
