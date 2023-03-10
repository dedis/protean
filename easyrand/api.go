package easyrand

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyrand/base"
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

func (c *Client) InitUnit(threshold int) (*InitUnitReply, error) {
	req := &InitUnitRequest{Roster: c.roster, Threshold: threshold}
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

func (c *Client) CreateRandomness() (*CreateRandomnessReply, error) {
	req := &CreateRandomnessRequest{}
	reply := &CreateRandomnessReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) GetRandomness(round uint64,
	execReq *core.ExecutionRequest) (*GetRandomnessReply, error) {
	req := &GetRandomnessRequest{
		Input:   base.RandomnessInput{Round: round},
		ExecReq: *execReq,
	}
	reply := &GetRandomnessReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}
