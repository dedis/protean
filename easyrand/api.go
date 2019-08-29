package easyrand

import (
	"time"

	"github.com/dedis/protean/sys"
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

//func (c *Client) InitUnit(roster *onet.Roster, scData *sys.ScInitData, bStore *sys.BaseStorage, interval time.Duration, typeDur time.Duration, timeout time.Duration) (*InitUnitReply, error) {
func (c *Client) InitUnit(roster *onet.Roster, scCfg *sys.ScConfig, bStore *sys.BaseStorage, interval time.Duration, typeDur time.Duration, timeout time.Duration) (*InitUnitReply, error) {
	c.roster = roster
	req := &InitUnitRequest{
		Cfg: &sys.UnitConfig{
			Roster:       roster,
			ScCfg:        scCfg,
			BaseStore:    bStore,
			BlkInterval:  interval,
			DurationType: typeDur,
		},
		Timeout: timeout,
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
