package protocol

import (
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const NameReadState = "ReadState"

func init() {
	network.RegisterMessages(&Request{}, &Response{})
}

type VerifyRSRequest func(cid byzcoin.InstanceID, data []byte) bool

type Request struct {
	CID  byzcoin.InstanceID
	Data []byte
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
