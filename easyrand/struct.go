package easyrand

import (
	"time"

	"github.com/dedis/protean"
	"go.dedis.ch/onet/v3"
)

type InitUnitRequest struct {
	Roster       *onet.Roster
	ScData       *protean.ScInitData
	BaseStore    *protean.BaseStorage
	BlkInterval  time.Duration
	DurationType time.Duration
	// Timeout waiting for final signature - originally 2 seconds
	Timeout time.Duration
}

type InitUnitReply struct {
	Genesis []byte
}

type InitDKGRequest struct {
	// Timeout waiting for DKG to finish - originally 5 seconds
	Timeout int
}

// InitDKGReply is the response of DKG.
type InitDKGReply struct {
}

// RandomnessRequest is a request to get the public randomness.
type RandomnessRequest struct {
}

// RandomnessReply is the returned public randomness.
type RandomnessReply struct {
	Round uint64
	Sig   []byte
}
