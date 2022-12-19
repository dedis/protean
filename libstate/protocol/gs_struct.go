package protocol

import (
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const NameGetState = "GetState"

func init() {
	network.RegisterMessages(&GSRequest{}, &GSResponse{})
}

type VerifyGetStateRequest func(cid byzcoin.InstanceID, data []byte) bool

type GSRequest struct {
	CID  byzcoin.InstanceID
	Data []byte
}

type StructGSRequest struct {
	*onet.TreeNode
	GSRequest
}

type GSResponse struct {
	Signature protocol.BlsSignature
}

type StructGSResponse struct {
	*onet.TreeNode
	GSResponse
}
