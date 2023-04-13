package service

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const (
	UID string = "dummyunit"
)

func init() {
	network.RegisterMessages(&DummyRequest{}, &DummyReply{})
}

type DummyRequest struct {
	Roster     *onet.Roster
	OutputData map[string][]byte
}

type DummyReply struct{}
