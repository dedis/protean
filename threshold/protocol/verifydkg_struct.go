package protocol

import (
	"github.com/dedis/protean/core"
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const VerifyDKGProtoName = "threshold_verifydkg"

func init() {
	network.RegisterMessages()
}

type VerifyRequest struct {
	ExecReq *core.ExecutionRequest
}

type structVerifyRequest struct {
	*onet.TreeNode
	VerifyRequest
}

type VerifyResponse struct {
	Signatures map[string]blscosi.BlsSignature
}

type structVerifyResponse struct {
	*onet.TreeNode
	VerifyResponse
}
