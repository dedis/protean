package inittxn

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const ProtoName = "inittxn"

func init() {
	network.RegisterMessages(&Request{}, &Response{})
}

type GenerateFn func(input *base.InitTxnInput) (*core.ExecutionPlan, error)

type Request struct {
	Input *base.InitTxnInput
	Data  []byte
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
