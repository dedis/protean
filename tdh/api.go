package tdh

import (
	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"

	"go.dedis.ch/onet/v3"
)

type Client struct {
	*onet.Client
	roster *onet.Roster
}

func NewClient(r *onet.Roster) *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName), roster: r}
}

//func (c *Client) InitUnit(scCfg *sys.ScConfig, bStore *sys.BaseStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
//req := &InitUnitRequest{
//Cfg: &sys.UnitConfig{
//Roster:       c.roster,
//ScCfg:        scCfg,
//BaseStore:    bStore,
//BlkInterval:  interval,
//DurationType: typeDur,
//},
//}
//reply := &InitUnitReply{}
//err := c.SendProtobuf(c.roster.List[0], req, reply)
//return reply, err
//}

func (c *Client) InitUnit(cfg *sys.UnitConfig) (*InitUnitReply, error) {
	req := &InitUnitRequest{Cfg: cfg}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) InitDKG(id []byte, ed *sys.ExecutionData) (*InitDKGReply, error) {
	req := &InitDKGRequest{
		ID:       NewDKGID(id),
		ExecData: ed,
	}
	reply := &InitDKGReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) Decrypt(id []byte, gen []byte, ct *Ciphertext, xc kyber.Point, ed *sys.ExecutionData) (*DecryptReply, error) {
	req := &DecryptRequest{
		ID:       NewDKGID(id),
		Gen:      gen,
		Ct:       ct,
		Xc:       xc,
		ExecData: ed,
	}
	reply := &DecryptReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

//func GetServiceID() onet.ServiceID {
//return tdhID
//}
