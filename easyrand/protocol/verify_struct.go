package protocol

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyrand/base"
	"go.dedis.ch/cothority/v3/blscosi/bdnproto"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const VerifyProtoName = "easyrand_verify"

func init() {
	network.RegisterMessages(&VerifyRand{}, &VerifyResponse{})
}

type VerifyRand struct {
	Input   *base.RandomnessInput
	ExecReq *core.ExecutionRequest
}

type structVerifyRand struct {
	*onet.TreeNode
	VerifyRand
}

type VerifyResponse struct {
	Signatures map[string]bdnproto.BdnSignature
}

type structVerifyResponse struct {
	*onet.TreeNode
	VerifyResponse
}
