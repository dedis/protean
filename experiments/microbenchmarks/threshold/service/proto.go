package service

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/threshold/base"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(&InitDKGRequest{}, &InitDKGReply{},
		&DecryptRequest{}, &DecryptReply{})
}

type DKGID [32]byte

type InitDKGRequest struct {
	Roster    *onet.Roster
	Threshold int
	ID        DKGID
}

type InitDKGReply struct {
	Output base.DKGOutput
}

type DecryptRequest struct {
	Roster    *onet.Roster
	Threshold int
	IsRegular bool
	ID        DKGID
	Input     base.DecryptInput
}

type DecryptReply struct {
	Output         base.DecryptOutput
	OutputReceipts map[string]*core.OpcodeReceipt
}

// Internal structs

type pubPoly struct {
	B       kyber.Point
	Commits []kyber.Point
}
