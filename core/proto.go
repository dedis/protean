package core

import (
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/onet/v3"
)

type TestSignRequest struct {
	Roster *onet.Roster
	Msg    []byte
}

type TestSignReply struct {
	Hash      []byte
	Signature protocol.BlsSignature
}
