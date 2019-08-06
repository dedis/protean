package easyrand

import (
	"time"

	"github.com/dedis/protean"
	"go.dedis.ch/onet/v3"
)

type InitUnitRequest struct {
	ScData       *protean.ScInitData
	BaseStore    *protean.BaseStorage
	BlkInterval  time.Duration
	DurationType time.Duration
}

type InitUnitReply struct {
	Genesis []byte
}

type InitDKGRequest struct {
	Roster *onet.Roster
}

// InitDKGReply is the response of DKG.
type InitDKGReply struct {
}

// RandomnessRequest is a request to get the public randomness.
type RandomnessRequest struct {
	Roster *onet.Roster
}

// RandomnessReply is the returned public randomness.
type RandomnessReply struct {
	Round uint64
	Sig   []byte
}
