package threshold

import (
	"github.com/dedis/protean/sys"
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
	Cfg *sys.UnitConfig
}

type InitUnitReply struct {
	Genesis []byte
}

type InitDKGRequest struct {
	ExecData *sys.ExecutionData
	ID       DKGID
}

type InitDKGReply struct {
	X   kyber.Point
	Sig protocol.BlsSignature
}

type DecryptRequest struct {
	ExecData *sys.ExecutionData
	ID       DKGID
	Cs       []*utils.ElGamalPair
	// Server is a flag that specifies where the secret reconstruction is
	// going to happen. If true, threshold unit handles the secret
	// reconstruction. If false, threshold unit returns the partial
	// decryptions and decryption proofs to the client
	Server bool
}

type DecryptReply struct {
	// If server = true, Ps will contain the plaintext. If server =
	// false, Ps will be nil
	Ps []kyber.Point
	// If server = false, Partials will contain the partial decryptions and
	// decryption proofs. If server = true, Partials will be nil
	Partials []*Partial
	Sig      protocol.BlsSignature
}

// Protocol messages
type Share struct {
	Sh *share.PubShare
	Ei kyber.Scalar
	Fi kyber.Scalar
}

type Partial struct {
	Shares []*share.PubShare
	Eis    []kyber.Scalar
	Fis    []kyber.Scalar
	Pubs   []kyber.Point
}

type PartialRequest struct {
	Cs []*utils.ElGamalPair
}

type structPartialRequest struct {
	*onet.TreeNode
	PartialRequest
}

type PartialReply struct {
	Shares []*Share
}

type structPartialReply struct {
	*onet.TreeNode
	PartialReply
}

// Internal structs

type pubPoly struct {
	B       kyber.Point
	Commits []kyber.Point
}
