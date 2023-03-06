package protocol

import (
	"github.com/dedis/protean/core"
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const SignProtoName = "microbenchmark_sign"

func init() {
	network.RegisterMessages(&SignRequest{}, &SignResponse{})
}

type SignRequest struct {
	OutputData map[string][]byte
	ExecReq    *core.ExecutionRequest
}

type structSign struct {
	*onet.TreeNode
	SignRequest
}

type SignResponse struct {
	Signatures map[string]blscosi.BlsSignature
}

type structSignResponse struct {
	*onet.TreeNode
	SignResponse
}
