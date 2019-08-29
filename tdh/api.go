package tdh

import (
	"time"

	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"

	"go.dedis.ch/onet/v3"
)

type Client struct {
	*onet.Client
	roster *onet.Roster
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}

//func (c *Client) InitUnit(roster *onet.Roster, scData *sys.ScInitData, bStore *sys.BaseStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
func (c *Client) InitUnit(roster *onet.Roster, scCfg *sys.ScConfig, bStore *sys.BaseStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
	c.roster = roster
	req := &InitUnitRequest{
		Cfg: &sys.UnitConfig{
			Roster:       roster,
			ScCfg:        scCfg,
			BaseStore:    bStore,
			BlkInterval:  interval,
			DurationType: typeDur,
		},
	}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) InitDKG(id []byte) (*InitDKGReply, error) {
	req := &InitDKGRequest{
		ID: NewDKGID(id),
	}
	reply := &InitDKGReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) Decrypt(id []byte, gen []byte, ct *Ciphertext, xc kyber.Point) (*DecryptReply, error) {
	req := &DecryptRequest{
		ID:  NewDKGID(id),
		Gen: gen,
		Ct:  ct,
		Xc:  xc,
	}
	reply := &DecryptReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}
