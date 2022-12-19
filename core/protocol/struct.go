package protocol

import (
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const NameTestBlsCosi = "TestBlsCosi"

func init() {
	network.RegisterMessages(&Request{}, &Response{})
}

type Request struct {
	ReqData []byte
}

type StructRequest struct {
	*onet.TreeNode
	Request
}

type Response struct {
	Data      []byte
	Signature protocol.BlsSignature
}

type StructResponse struct {
	*onet.TreeNode
	Response
}
