package execute

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	"go.dedis.ch/cothority/v3/blscosi/bdnproto"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const ProtoName = "execute"

func init() {
	network.RegisterMessages(&Request{}, &Response{})
}

type Request struct {
	Input   *base.ExecuteInput
	ExecReq *core.ExecutionRequest
}

type StructRequest struct {
	*onet.TreeNode
	Request
}

type Response struct {
	InSignatures  map[string]bdnproto.BdnSignature
	OutSignatures map[string]bdnproto.BdnSignature
}

type StructResponse struct {
	*onet.TreeNode
	Response
}
