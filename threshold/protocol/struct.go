package protocol

import (
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
)

const DecryptProtoName = "threshold_decrypt"

type Partial struct {
	Shares []*share.PubShare
	Eis    []kyber.Scalar
	Fis    []kyber.Scalar
}

type DecryptShare struct {
	Cs []utils.ElGamalPair
}

type structDecryptShare struct {
	*onet.TreeNode
	DecryptShare
}

type Share struct {
	Sh *share.PubShare
	Ei kyber.Scalar
	Fi kyber.Scalar
}

type DecryptShareResponse struct {
	Shares []Share
}

type structDecryptShareResponse struct {
	*onet.TreeNode
	DecryptShareResponse
}

type Reconstruct struct {
	Partials []Partial
	Publics  map[int]kyber.Point
	Hash     []byte
}

type structReconstruct struct {
	*onet.TreeNode
	Reconstruct
}

type ReconstructResponse struct {
	Signature protocol.BlsSignature
}

type structReconstructResponse struct {
	*onet.TreeNode
	ReconstructResponse
}
