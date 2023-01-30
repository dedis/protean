package execute

import (
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const ProtoName = "execute"

func init() {
	network.RegisterMessages(&Request{}, &Response{})
}

//type GenerateFn func(data []byte) (*core.ExecutionPlan, error)

type Request struct {
}

type StructRequest struct {
	*onet.TreeNode
	Request
}

type Response struct {
	Signature protocol.BlsSignature
}

type StructResponse struct {
	*onet.TreeNode
	Response
}
