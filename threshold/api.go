package threshold

import (
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
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

func (c *Client) InitDKG(id []byte) (*InitDKGReply, error) {
	req := &InitDKGRequest{
		ID: NewDKGID(id),
	}
	reply := &InitDKGReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) Decrypt(id []byte, cs []utils.ElGamalPair) (*DecryptReply, error) {
	req := &DecryptRequest{
		ID: NewDKGID(id),
		Cs: cs,
	}
	reply := &DecryptReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func GetServiceID() onet.ServiceID {
	return thresholdID
}
