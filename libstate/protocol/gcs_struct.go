package protocol

import (
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const GCSProtocol = "GCSProtocol"

func init() {
	network.RegisterMessages(&GCSRequest{}, &GCSResponse{})
}

type VerifyGCSRequest func(cid byzcoin.InstanceID, data []byte) bool

type GCSRequest struct {
	CID        byzcoin.InstanceID
	ProofBytes []byte
	Keys       []string
}

type StructGCSRequest struct {
	*onet.TreeNode
	GCSRequest
}

type GCSResponse struct {
	Signature protocol.BlsSignature
}

type StructGCSResponse struct {
	*onet.TreeNode
	GCSResponse
}
