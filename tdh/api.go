package tdh

import (
	"time"

	"github.com/dedis/protean"
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

func (c *Client) InitUnit(roster *onet.Roster, scData *protean.ScInitData, bStore *protean.BaseStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
	c.roster = roster
	req := &InitUnitRequest{
		Roster:       roster,
		ScData:       scData,
		BaseStore:    bStore,
		BlkInterval:  interval,
		DurationType: typeDur,
	}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) InitDKG(id []byte) (*InitDKGReply, error) {
	//hexID := hex.EncodeToString(id)
	req := &InitDKGRequest{
		//ID: hexID,
		ID: NewDKGID(id),
	}
	reply := &InitDKGReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

//func (c *Client) Decrypt(id []byte, gen []byte, cP kyber.Point, u kyber.Point, xc kyber.Point) (*DecryptReply, error) {
func (c *Client) Decrypt(id []byte, gen []byte, ct *Ciphertext, xc kyber.Point) (*DecryptReply, error) {
	//hexID := hex.EncodeToString(id)
	req := &DecryptRequest{
		//ID:  hexID,
		ID:  NewDKGID(id),
		Gen: gen,
		Ct:  ct,
		Xc:  xc,
		//C:   cP,
		//U:   u,
	}
	reply := &DecryptReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}
