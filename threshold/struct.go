package threshold

import (
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
)

const ThreshProtoName = "ThreshDecryptProto"
const DKG = "InitDKG"
const DEC = "Decrypt"

type DKGID [32]byte

type InitUnitRequest struct {
	Roster *onet.Roster
}

type InitUnitReply struct{}

type InitDKGRequest struct {
	ID DKGID
	//ExecData *sys.ExecutionData
}

type InitDKGReply struct {
	X   kyber.Point
	Sig protocol.BlsSignature
}

type DecryptRequest struct {
	ID DKGID
	Cs []utils.ElGamalPair
	//ExecData *sys.ExecutionData
}

type DecryptReply struct {
	Ps        []kyber.Point
	Signature protocol.BlsSignature
}

//type DecryptReply struct {
//	// If server = true, Ps will contain the plaintext. If server =
//	// false, Ps will be nil
//	Ps []kyber.Point
//	// If server = false, partials will contain the partial decryptions and
//	// decryption proofs. If server = true, partials will be nil
//	partials  []*Partial
//	Signature protocol.BlsSignature
//}

type Partial struct {
	Shares []*share.PubShare
	Eis    []kyber.Scalar
	Fis    []kyber.Scalar
	//Pubs   []kyber.Point
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

type DecryptShareReply struct {
	Shares []Share
}

type structDecryptShareReply struct {
	*onet.TreeNode
	DecryptShareReply
}

type Reconstruct struct {
	Partials []Partial
	//Publics  []kyber.Point
	Publics map[int]kyber.Point
	Hash    []byte
}

type structReconstruct struct {
	*onet.TreeNode
	Reconstruct
}

type ReconstructReply struct {
	Signature protocol.BlsSignature
}

type structReconstructReply struct {
	*onet.TreeNode
	ReconstructReply
}

// Internal structs

type pubPoly struct {
	B       kyber.Point
	Commits []kyber.Point
}
