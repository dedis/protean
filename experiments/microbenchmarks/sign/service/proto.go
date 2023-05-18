package service

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const (
	UID string = "signer"
)

func init() {
	network.RegisterMessages(&BLSSignRequest{}, &BLSSignReply{}, &BDNSignRequest{},
		&BDNSignReply{})
}

type BLSSignRequest struct {
	Roster     *onet.Roster
	OutputData map[string][]byte
	ExecReq    *core.ExecutionRequest
}

type BLSSignReply struct {
	Receipts map[string]*core.OpcodeReceipt
}

type BDNSignRequest struct {
	Roster     *onet.Roster
	OutputData map[string][]byte
	ExecReq    *core.ExecutionRequest
}

type BDNSignReply struct {
	Receipts map[string]*core.OpcodeReceipt
}
