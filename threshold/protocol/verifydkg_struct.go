package protocol

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/blscosi/bdnproto"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const VerifyDKGProtoName = "threshold_verifydkg"

func init() {
	network.RegisterMessages(&VerifyRequest{}, &VerifyResponse{})
}

type VerifyRequest struct {
	ExecReq *core.ExecutionRequest
}

type structVerifyRequest struct {
	*onet.TreeNode
	VerifyRequest
}

type VerifyResponse struct {
	Signatures map[string]bdnproto.BdnSignature
}

type structVerifyResponse struct {
	*onet.TreeNode
	VerifyResponse
}
