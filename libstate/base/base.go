package base

import (
	"crypto/sha256"
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/byzcoin"
)

const (
	UID           string = "state"
	INIT_CONTRACT string = "init_contract"
	UPDATE_STATE  string = "update_state"
)

type VerifyFn func(*UpdateInput, *core.ExecutionRequest) bool

type UpdateInput struct {
	Txn byzcoin.ClientTransaction
}

func (input *UpdateInput) PrepareInputHashes() map[string][]byte {
	inputHashes := make(map[string][]byte)
	h := sha256.New()
	for _, inst := range input.Txn.Instructions {
		for _, arg := range inst.Invoke.Args {
			h.Write([]byte(arg.Name))
			h.Write(arg.Value)
		}
	}
	inputHashes["ws"] = h.Sum(nil)
	return inputHashes
}

func Hash(args byzcoin.Arguments) []byte {
	h := sha256.New()
	for _, arg := range args {
		h.Write([]byte(arg.Name))
		h.Write(arg.Value)
	}
	return h.Sum(nil)
}
