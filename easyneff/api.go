package easyneff

import (
	"errors"
	"fmt"
	"time"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
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

//func (c *Client) InitUnit(roster *onet.Roster, scData *sys.ScInitData, bStore *sys.BaseStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
func (c *Client) InitUnit(roster *onet.Roster, scCfg *sys.ScConfig, bStore *sys.BaseStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
	c.roster = roster
	req := &InitUnitRequest{
		Cfg: &sys.UnitConfig{
			Roster:       roster,
			ScCfg:        scCfg,
			BaseStore:    bStore,
			BlkInterval:  interval,
			DurationType: typeDur,
		},
	}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

//func (c *Client) Shuffle(pairs []ElGamalPair, g kyber.Point, h kyber.Point) (*ShuffleReply, error) {
func (c *Client) Shuffle(pairs []utils.ElGamalPair, g kyber.Point, h kyber.Point) (*ShuffleReply, error) {
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
//func (r *ShuffleReply) ShuffleVerify(G, H kyber.Point, initialPairs []ElGamalPair, publics []kyber.Point) error {
func (r *ShuffleReply) ShuffleVerify(G, H kyber.Point, initialPairs []utils.ElGamalPair, publics []kyber.Point) error {
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

// Verify performs verifies the proof of a Neff shuffle.
func Verify(prf []byte, G, H kyber.Point, x, y, xbar, ybar []kyber.Point) error {
	if len(x) < 2 || len(y) < 2 || len(xbar) < 2 || len(ybar) < 2 {
		return errors.New("cannot verify less than 2 points")
	}
	verifier := shuffle.Verifier(cothority.Suite, G, H, x, y, xbar, ybar)
	return proof.HashVerify(cothority.Suite, "", verifier, prf)
}
