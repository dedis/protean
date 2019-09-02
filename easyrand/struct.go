package easyrand

import (
	"time"

	"github.com/dedis/protean/sys"
	"go.dedis.ch/kyber/v3"
)

const RAND = "Randomness"

type InitUnitRequest struct {
	Cfg     *sys.UnitConfig
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
	Public kyber.Point
}

// RandomnessRequest is a request to get the public randomness.
type RandomnessRequest struct{}

// RandomnessReply is the returned public randomness.
type RandomnessReply struct {
	Round uint64
	Prev  []byte
	Sig   []byte
}
