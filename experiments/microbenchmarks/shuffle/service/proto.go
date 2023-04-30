package service

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyneff/base"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(&DummyRequest{}, &DummyReply{},
		&ShuffleRequest{}, &ShuffleReply{})
}

type DummyRequest struct {
	Roster    *onet.Roster
	Threshold int
	Input     base.ShuffleInput
	IsRegular bool
}

type DummyReply struct{}

type ShuffleRequest struct {
	Roster    *onet.Roster
	Threshold int
	Input     base.ShuffleInput
	IsRegular bool
}

type ShuffleReply struct {
	Proofs         base.ShuffleOutput
	OutputReceipts map[string]*core.OpcodeReceipt
}
