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

func NewClient(r *onet.Roster) *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName), roster: r}
}

func (c *Client) InitUnit(scData *protean.ScInitData, bStore *protean.BaseStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
	req := &InitUnitRequest{
		ScData:       scData,
		BaseStore:    bStore,
		BlkInterval:  interval,
		DurationType: typeDur,
	}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}
