package easyrand

import (
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

func (c *Client) InitDKG() (*InitDKGReply, error) {
	req := &InitDKGRequest{}
	reply := &InitDKGReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) Randomness() (*RandomnessReply, error) {
	req := &RandomnessRequest{}
	reply := &RandomnessReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}
