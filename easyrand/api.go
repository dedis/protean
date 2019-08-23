package easyrand

import (
	"time"

	"github.com/dedis/protean"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
)

type Client struct {
	*onet.Client
	roster *onet.Roster
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}

func (c *Client) InitUnit(roster *onet.Roster, scData *protean.ScInitData, bStore *protean.BaseStorage, interval time.Duration, typeDur time.Duration, timeout time.Duration) (*InitUnitReply, error) {
	c.roster = roster
	req := &InitUnitRequest{
		Roster:       roster,
		ScData:       scData,
		BaseStore:    bStore,
		BlkInterval:  interval,
		DurationType: typeDur,
		Timeout:      timeout,
	}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) InitDKG(timeout int) (*InitDKGReply, error) {
	req := &InitDKGRequest{
		Timeout: timeout,
	}
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
