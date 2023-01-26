package easyneff

import (
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"golang.org/x/xerrors"
)

type Client struct {
	*onet.Client
	roster *onet.Roster
}

func NewClient(r *onet.Roster) *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName), roster: r}
}

func (c *Client) InitUnit() (*InitUnitReply, error) {
	req := &InitUnitRequest{Roster: c.roster}
	reply := &InitUnitReply{}
	for _, dst := range c.roster.List {
		err := c.SendProtobuf(dst, req, reply)
		if err != nil {
			return nil, err
		}
	}
	return reply, nil
}

func (c *Client) Shuffle(pairs []utils.ElGamalPair, h kyber.Point) (*ShuffleReply, error) {
	if len(pairs) <= 0 {
		return nil, xerrors.Errorf("No ciphertext to shuffle")
	}
	req := &ShuffleRequest{
		Pairs: pairs,
		H:     h,
	}
	reply := &ShuffleReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}
