package verify

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libstate/base"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const ProtoName = "libexec_verify"

func init() {
	network.RegisterMessages(&Request{}, &Response{})
}

type Request struct {
	Input   *base.UpdateInput
	ExecReq *core.ExecutionRequest
}

type structRequest struct {
	*onet.TreeNode
	Request
}

type Response struct {
	Verified bool
}

type structResponse struct {
	*onet.TreeNode
	Response
}
