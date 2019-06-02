package easyneff

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

// Request is a message that the client sends to initiate Neff shuffle. The
// points G and H are public generators used in ElGamal encryption.
type Request struct {
	Pairs  []ElGamalPair
	G, H   kyber.Point
	Roster *onet.Roster
}

// Response is the result of all the proofs of the shuffle. The client is
// responsible for verifying the result.
type Response struct {
	Proofs []Proof
}

// ElGamalPair is an ElGamal ciphertext.
type ElGamalPair struct {
	C1 kyber.Point
	C2 kyber.Point
}

// Proof is the Neff shuffle proof with a signature.
type Proof struct {
	Pairs     []ElGamalPair
	Proof     []byte
	Signature []byte // on the Proof
}
