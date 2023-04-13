package verify

import (
	"github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/utils"
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const VerifyProtoName = "mb_shuffle_verify"

func init() {
	network.RegisterMessages(&Verify{}, &VerifyResponse{})
}

type VerificationFn func(*base.ShuffleOutput, kyber.Point, kyber.Point,
	utils.ElGamalPairs, []kyber.Point) error

type Verify struct {
	ShufInput  *base.ShuffleInput
	ShufOutput *base.ShuffleOutput
}

type structVerify struct {
	*onet.TreeNode
	Verify
}

type VerifyResponse struct {
	Signatures map[string]blscosi.BlsSignature
}

type structVerifyResponse struct {
	*onet.TreeNode
	VerifyResponse
}
