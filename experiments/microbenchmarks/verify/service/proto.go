package service

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/onet/v3"
)

const (
	UID string = "verifier"
)

type VerifyRequest struct {
	Roster      *onet.Roster
	InputData   map[string][]byte
	StateProofs map[string]*core.StateProof
	ExecReq     *core.ExecutionRequest
}

type VerifyReply struct {
	Success bool
}
