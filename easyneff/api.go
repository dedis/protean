package easyneff

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyneff/base"
	protean "github.com/dedis/protean/utils"
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

func (c *Client) InitUnit(threshold int) (*InitUnitReply, error) {
	req := &InitUnitRequest{Roster: c.roster, Threshold: threshold}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	if err != nil {
		return nil, xerrors.Errorf("send InitUnit message: %v", err)
	}
	return reply, nil
}

func (c *Client) Shuffle(ps protean.ElGamalPairs, H kyber.Point, execReq *core.ExecutionRequest) (*ShuffleReply, error) {
	if len(ps.Pairs) <= 0 {
		return nil, xerrors.Errorf("No ciphertext to shuffle")
	}
	req := &ShuffleRequest{
		Input: base.ShuffleInput{
			Pairs: ps,
			H:     H,
		},
		ExecReq: *execReq,
	}
	reply := &ShuffleReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}
