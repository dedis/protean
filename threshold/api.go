package threshold

import (
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

func (c *Client) Decrypt(id []byte, cs []*utils.ElGamalPair, server bool, ed *sys.ExecutionData) (*DecryptReply, error) {
	req := &DecryptRequest{
		ID:       NewDKGID(id),
		Cs:       cs,
		Server:   server,
		ExecData: ed,
	}
	reply := &DecryptReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func RecoverMessages(numNodes int, cs []*utils.ElGamalPair, partials []*Partial) []kyber.Point {
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
		ps[i] = recoverCommit(numNodes, cs[i], validShares)
	}
	return ps
}

func GetServiceID() onet.ServiceID {
	return thresholdID
}
