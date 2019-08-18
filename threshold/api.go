package threshold

import (
	"encoding/hex"
	"time"

	"github.com/dedis/protean"
	"github.com/dedis/protean/utils"
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
	hexID := hex.EncodeToString(id)
	req := &InitDKGRequest{
		ID: hexID,
	}
	reply := &InitDKGReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

//func (c *Client) Decrypt(id []byte, c1 kyber.Point, c2 kyber.Point) (*DecryptReply, error) {
func (c *Client) Decrypt(id []byte, cs []*utils.ElGamalPair) (*DecryptReply, error) {
	hexID := hex.EncodeToString(id)
	//ct := &Ciphertext{
	//C1: c1,
	//C2: c2,
	//}
	req := &DecryptRequest{
		ID: hexID,
		//Ciphertext: ct,
		Cs: cs,
	}
	reply := &DecryptReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

//func (c *Client) RecoverPlaintext(reply *DecryptReply, xc kyber.Scalar) ([]byte, error) {
//var data []byte
//var err error
//if xc == nil {
//xHatInv := cothority.Suite.Point().Neg(reply.XhatEnc)
//dataPt := cothority.Suite.Point().Add(reply.C, xHatInv)
//data, err = dataPt.Data()
//} else {
//xcInv := xc.Clone().Neg(xc)
//xHatDec := reply.X.Clone().Mul(xcInv, reply.X)
//xHat := xHatDec.Clone().Add(reply.XhatEnc, xHatDec)
//xHatInv := xHat.Clone().Neg(xHat)
//xHatInv.Add(reply.C, xHatInv)
//data, err = xHatInv.Data()
//}
//return data, err
//}
