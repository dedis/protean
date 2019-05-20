package easyrand

import "go.dedis.ch/onet/v3"

// InitDKGReq is a request to start the DKG.
type InitDKGReq struct {
	Roster *onet.Roster
}

// InitDKGResp is the response of DKG.
type InitDKGResp struct {
}

// RandomnessReq is a request to get the public randomness.
type RandomnessReq struct {
	Roster *onet.Roster
}

// RandomnessResp is the returned public randomness.
type RandomnessResp struct {
	Round uint64
	Sig   []byte
}
