package protocol

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const VerifyProtoName = "microbenchmark_verify"

func init() {
	network.RegisterMessages(&VerifyRequest{}, &VerifyResponse{})
}

type VerifyRequest struct {
	InputData   map[string][]byte
	StateProofs map[string]*core.StateProof
	Precommits  *core.KVDict
	ExecReq     *core.ExecutionRequest
}

type structVerify struct {
	*onet.TreeNode
	VerifyRequest
}

type VerifyResponse struct {
	Success bool
}

type structVerifyResponse struct {
	*onet.TreeNode
	VerifyResponse
}
