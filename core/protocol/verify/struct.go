package verify

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const Name = "Verify"

var suite = pairing.NewSuiteBn256()

func init() {
	network.RegisterMessages(&VRequest{}, &VResponse{})
}

type VRequest struct {
	ExecReq      core.ExecutionRequest
	OpcodeHashes map[string][]byte
	KVMap        map[string]core.ReadState
	UID          string
	OpcodeName   string
	SUID         string
	CEUID        string
}

type StructVRequest struct {
	*onet.TreeNode
	VRequest
}

type VResponse struct {
	Success bool
}

type StructVResponse struct {
	*onet.TreeNode
	VResponse
}
