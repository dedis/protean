package protocol

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/utils"
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const VerifyProtoName = "easyneff_verify"

func init() {
	network.RegisterMessages(&VerifyProofs{}, &VerifyProofsResponse{})
}

type VerificationFn func(*base.ShuffleOutput, kyber.Point, kyber.Point,
	utils.ElGamalPairs, []kyber.Point) error

type VerifyProofs struct {
	ShufInput  *base.ShuffleInput
	ShufOutput *base.ShuffleOutput
	ExecReq    *core.ExecutionRequest
}

type structVerifyProofs struct {
	*onet.TreeNode
	VerifyProofs
}

type VerifyProofsResponse struct {
	Signatures map[string]blscosi.BlsSignature
}

type structVerifyProofsResponse struct {
	*onet.TreeNode
	VerifyProofsResponse
}
