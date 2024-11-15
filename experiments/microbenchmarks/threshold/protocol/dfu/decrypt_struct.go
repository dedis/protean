package dfu

import (
	"github.com/dedis/protean/threshold/base"
	"go.dedis.ch/cothority/v3/blscosi/bdnproto"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const DFUDecryptProtoName = "decrypt_dfu"

func init() {
	network.RegisterMessages(&DecryptShare{}, &DecryptShareResponse{},
		&Reconstruct{}, &ReconstructResponse{})
}

type Partial struct {
	Shares []*share.PubShare
	Eis    []kyber.Scalar
	Fis    []kyber.Scalar
}

type DecryptShare struct {
	*base.DecryptInput
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
	Threshold int
	Partials  []Partial
	Publics   map[int]kyber.Point
}

type structReconstruct struct {
	*onet.TreeNode
	Reconstruct
}

type ReconstructResponse struct {
	Signatures map[string]bdnproto.BdnSignature
}

type structReconstructResponse struct {
	*onet.TreeNode
	ReconstructResponse
}
