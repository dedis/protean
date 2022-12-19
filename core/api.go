package core

import (
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
)

type Client struct {
	*onet.Client
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}

func (c *Client) TestSigning(r *onet.Roster, msg []byte) (*TestSignReply, error) {
	req := &TestSignRequest{
		Roster: r,
		Msg:    msg,
	}
	reply := &TestSignReply{}
	err := c.SendProtobuf(r.List[0], req, reply)
	return reply, err
}
