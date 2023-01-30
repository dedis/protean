package easyrand

import (
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

const DKG = "InitDKG"
const RAND = "Randomness"

type InitUnitRequest struct {
	Roster *onet.Roster
}

type InitUnitReply struct{}

type InitDKGRequest struct{}

// InitDKGReply is the response of DKG.
type InitDKGReply struct {
	Public kyber.Point
}

// RandomnessRequest is a request to get the public randomness.
type RandomnessRequest struct{}

// RandomnessReply is the returned public randomness.
type RandomnessReply struct {
	Public kyber.Point
	Round  uint64
	Prev   []byte
	// Value is the collective signature. Use the hash of it!
	Value     []byte
	Signature blscosi.BlsSignature
}
