package threshold

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/threshold/base"
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

func (c *Client) InitDKG(execReq *core.ExecutionRequest) (*InitDKGReply, error) {
	req := &InitDKGRequest{
		ExecReq: *execReq,
	}
	reply := &InitDKGReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) Decrypt(input *base.DecryptInput, execReq *core.ExecutionRequest) (
	*DecryptReply, error) {
	req := &DecryptRequest{
		Input:   *input,
		ExecReq: *execReq,
	}
	reply := &DecryptReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}
