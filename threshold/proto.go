package threshold

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/threshold/base"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&InitDKGRequest{}, &InitDKGReply{}, &DecryptRequest{},
		&DecryptReply{})
}

type DKGID [32]byte

type InitUnitRequest struct {
	Roster *onet.Roster
}

type InitUnitReply struct{}

type InitDKGRequest struct {
	ID      DKGID
	ExecReq core.ExecutionRequest
}

type InitDKGReply struct {
	X   kyber.Point
	Sig protocol.BlsSignature
}

type DecryptRequest struct {
	ID      DKGID
	Input   base.DecryptInput
	ExecReq core.ExecutionRequest
}

type DecryptReply struct {
	Ps        []kyber.Point
	Signature protocol.BlsSignature
}

// Internal structs

type pubPoly struct {
	B       kyber.Point
	Commits []kyber.Point
}
