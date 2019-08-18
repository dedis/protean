package easyneff

import (
	"errors"
	"fmt"
	"time"

	"github.com/dedis/protean"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/shuffle"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3"
)

type Client struct {
	*onet.Client
	roster *onet.Roster
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}

func (c *Client) InitUnit(roster *onet.Roster, scData *protean.ScInitData, bStore *protean.BaseStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
	c.roster = roster
	req := &InitUnitRequest{
		Roster:       roster,
		ScData:       scData,
		BaseStore:    bStore,
		BlkInterval:  interval,
		DurationType: typeDur,
	}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) Shuffle(pairs []ElGamalPair, g kyber.Point, h kyber.Point) (*ShuffleReply, error) {
	if len(pairs) <= 0 {
		return nil, fmt.Errorf("No ciphertext to shuffle")
	}
	req := &ShuffleRequest{
		Pairs: pairs,
		G:     g,
		H:     h,
	}
	reply := &ShuffleReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

//TODO: Not sure if this is the right place for this function. To be seen once
//I start implementing the e-voting application
func (r *ShuffleReply) ShuffleVerify(G, H kyber.Point, initialPairs []ElGamalPair, publics []kyber.Point) error {
	x, y := splitPairs(initialPairs)
	for i, proof := range r.Proofs {
		// check that the signature on the proof is correct
		if err := schnorr.Verify(cothority.Suite, publics[i], proof.Proof, proof.Signature); err != nil {
			return err
		}
		// check that the shuffle is correct
		xbar, ybar := splitPairs(proof.Pairs)
		if err := Verify(proof.Proof, G, H, x, y, xbar, ybar); err != nil {
			return err
		}
		// reset the x and y for the next iteration
		x, y = xbar, ybar
	}
	return nil
}

//// Encrypt performs the ElGamal encryption algorithm.
//func Encrypt(public kyber.Point, message []byte) (K, C kyber.Point) {
//if len(message) > cothority.Suite.Point().EmbedLen() {
//panic("message size is too long")
//}
//M := cothority.Suite.Point().Embed(message, random.New())

//// ElGamal-encrypt the point to produce ciphertext (K,C).
//k := cothority.Suite.Scalar().Pick(random.New()) // ephemeral private key
//K = cothority.Suite.Point().Mul(k, nil)          // ephemeral DH public key
//S := cothority.Suite.Point().Mul(k, public)      // ephemeral DH shared secret
//C = S.Add(S, M)                                  // message blinded with secret
//return
//}

//// Decrypt performs the ElGamal decryption algorithm.
//func Decrypt(private kyber.Scalar, K, C kyber.Point) kyber.Point {
//// ElGamal-decrypt the ciphertext (K,C) to reproduce the message.
//S := cothority.Suite.Point().Mul(private, K) // regenerate shared secret
//return cothority.Suite.Point().Sub(C, S)     // use to un-blind the message
//}

// Verify performs verifies the proof of a Neff shuffle.
func Verify(prf []byte, G, H kyber.Point, x, y, xbar, ybar []kyber.Point) error {
	if len(x) < 2 || len(y) < 2 || len(xbar) < 2 || len(ybar) < 2 {
		return errors.New("cannot verify less than 2 points")
	}
	verifier := shuffle.Verifier(cothority.Suite, G, H, x, y, xbar, ybar)
	return proof.HashVerify(cothority.Suite, "", verifier, prf)
}
