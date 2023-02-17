package execute

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const ProtoName = "execute"

func init() {
	network.RegisterMessages(&Request{}, &Response{})
}

type Request struct {
	FnName  string
	Input   *base.ExecuteInput
	ExecReq *core.ExecutionRequest
}

type StructRequest struct {
	*onet.TreeNode
	Request
}

type Response struct {
	Signatures map[string]protocol.BlsSignature
}

type StructResponse struct {
	*onet.TreeNode
	Response
}
