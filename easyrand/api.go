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

func NewClient(r *onet.Roster) *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName), roster: r}
}

func (c *Client) InitUnit(cfg *sys.UnitConfig, timeout time.Duration) (*InitUnitReply, error) {
	req := &InitUnitRequest{
		Cfg:     cfg,
		Timeout: timeout,
	}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) InitDKG(timeout int, ed *sys.ExecutionData) (*InitDKGReply, error) {
	req := &InitDKGRequest{
		Timeout:  timeout,
		ExecData: ed,
	}
	reply := &InitDKGReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) Randomness(ed *sys.ExecutionData) (*RandomnessReply, error) {
	req := &RandomnessRequest{
		ExecData: ed,
	}
	reply := &RandomnessReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

//func GetServiceID() onet.ServiceID {
//return easyrandID
//}
