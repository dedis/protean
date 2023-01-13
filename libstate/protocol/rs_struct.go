package protocol

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const RSProtocol = "ReadState"

func init() {
	network.RegisterMessages(&RSRequest{}, &RSResponse{})
}

type VerifyRSRequest func(byzcoin.InstanceID, []byte, *core.StateProof) bool

type RSRequest struct {
	CID  byzcoin.InstanceID
	Data []byte
}

type StructRSRequest struct {
	*onet.TreeNode
	RSRequest
}

type RSResponse struct {
	Signature protocol.BlsSignature
}

type StructRSResponse struct {
	*onet.TreeNode
	RSResponse
}
