package service

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(&SignRequest{}, &SignReply{})
}

type SignRequest struct {
	Roster     *onet.Roster
	OutputData map[string][]byte
	ExecReq    *core.ExecutionRequest
}

type SignReply struct {
	Receipts map[string]*core.OpcodeReceipt
}
