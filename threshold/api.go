package threshold

import (
	"time"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"

	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

type Client struct {
	*onet.Client
	roster *onet.Roster
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}

//func (c *Client) InitUnit(roster *onet.Roster, scData *protean.ScInitData, bStore *protean.BaseStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
func (c *Client) InitUnit(roster *onet.Roster, scData *sys.ScInitData, bStore *sys.BaseStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
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
	req := &InitDKGRequest{
		ID: NewDKGID(id),
	}
	reply := &InitDKGReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) Decrypt(id []byte, cs []*utils.ElGamalPair, server bool) (*DecryptReply, error) {
	req := &DecryptRequest{
		ID:     NewDKGID(id),
		Cs:     cs,
		Server: server,
	}
	reply := &DecryptReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func RecoverMessages(numNodes int, cs []*utils.ElGamalPair, partials []*Partial) []kyber.Point {
	//var ps []kyber.Point
	ps := make([]kyber.Point, len(partials))
	for i, partial := range partials {
		var validShares []*share.PubShare
		for j, sh := range partial.Shares {
			ok := VerifyDecProof(sh.V, partial.Eis[j], partial.Fis[j], cs[i].K, partial.Pubs[j])
			if ok {
				validShares = append(validShares, sh)
			} else {
				log.Info("Cannot verify decryption proof from node", j)
			}
		}
		//ps = append(ps, recoverCommit(numNodes, cs[i], validShares))
		ps[i] = recoverCommit(numNodes, cs[i], validShares)
	}
	return ps
}
