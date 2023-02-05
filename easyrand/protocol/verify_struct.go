package protocol

import (
	"github.com/dedis/protean/core"
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/onet/v3"
)

const VerifyProtoName = "easyrand_verify"

type VerifyRand struct {
	ExecReq *core.ExecutionRequest
}

type structVerifyRand struct {
	*onet.TreeNode
	VerifyRand
}

type VerifyResponse struct {
	//Signature blscosi.BlsSignature
	Signatures map[string]blscosi.BlsSignature
}

type structVerifyResponse struct {
	*onet.TreeNode
	VerifyResponse
}
