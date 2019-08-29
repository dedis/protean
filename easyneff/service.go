package easyneff

import (
	"errors"
	"time"

	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

var serviceID onet.ServiceID

const ServiceName = "EasyNeffService"
const shuffleProtoName = "neffshuffle_protocol"

func init() {
	var err error
	serviceID, err = onet.RegisterNewService(ServiceName, newService)
	if err != nil {
		panic(err)
	}
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{}, &ShuffleRequest{}, &ShuffleReply{})
}

// EasyNeff is the service that runs a Neff shuffle.
type EasyNeff struct {
	*onet.ServiceProcessor
	scService   *skipchain.Service
	cosiService *blscosi.Service

	roster  *onet.Roster
	genesis skipchain.SkipBlockID
}

func (s *EasyNeff) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	cfg := req.Cfg
	/// Creating the skipchain here
	//genesisReply, err := utils.CreateGenesisBlock(s.scService, req.ScData, req.Roster)
	genesisReply, err := utils.CreateGenesisBlock(s.scService, req.Cfg.ScCfg, cfg.Roster)
	if err != nil {
		log.Errorf("Cannot create the skipchain genesis block: %v", err)
		return nil, err
	}
	s.genesis = genesisReply.Latest.Hash
	s.roster = cfg.Roster
	///////////////////////
	// Now adding a block with the unit information
	enc, err := protobuf.Encode(cfg.BaseStore)
	if err != nil {
		log.Errorf("Error in protobuf encoding: %v", err)
		return nil, err
	}
	err = utils.StoreBlock(s.scService, s.genesis, enc)
	if err != nil {
		return nil, err
	}
	return &InitUnitReply{Genesis: genesisReply.Latest.Hash}, nil
}

// Shuffle performs a shuffle request.
func (s *EasyNeff) Shuffle(req *ShuffleRequest) (*ShuffleReply, error) {
	//TODO: Protean stuff first
	// Now doing the actual shuffling
	// create a "line" tree
	tree := s.roster.GenerateNaryTree(1)
	pi, err := s.CreateProtocol(shuffleProtoName, tree)
	if err != nil {
		return nil, err
	}
	shufflePi := pi.(*ShuffleProtocol)
	shufflePi.InitialReq = *req
	if err := pi.Start(); err != nil {
		return nil, err
	}
	select {
	case proof := <-shufflePi.FinalProof:
		return &proof, nil
	case <-time.After(time.Second * time.Duration(len(s.roster.List))):
		return nil, errors.New("timeout waiting for shuffle proof")
	}
	//TODO: Do more Protean stuff
}

// Verify a convenience function to verify all the proofs. G and H are public
// generators. The initial ElGamal pairs must be given by initialPairs.
//func (r *ShuffleReply) Verify(G, H kyber.Point, initialPairs []ElGamalPair, publics []kyber.Point) error {
//x, y := splitPairs(initialPairs)
//for i, proof := range r.Proofs {
//// check that the signature on the proof is correct
//if err := schnorr.Verify(cothority.Suite, publics[i], proof.Proof, proof.Signature); err != nil {
//return err
//}
//// check that the shuffle is correct
//xbar, ybar := splitPairs(proof.Pairs)
//if err := Verify(proof.Proof, G, H, x, y, xbar, ybar); err != nil {
//return err
//}
//// reset the x and y for the next iteration
//x, y = xbar, ybar
//}
//return nil
//}

func newService(c *onet.Context) (onet.Service, error) {
	s := &EasyNeff{
		ServiceProcessor: onet.NewServiceProcessor(c),
		scService:        c.Service(skipchain.ServiceName).(*skipchain.Service),
		cosiService:      c.Service(blscosi.ServiceName).(*blscosi.Service),
	}
	err := s.RegisterHandlers(s.InitUnit, s.Shuffle)
	if err != nil {
		log.Errorf("Could not register handlers: %v", err)
		return nil, err

	}
	_, err = s.ProtocolRegister(shuffleProtoName, NewShuffleProtocolDefaultSuite)
	if err != nil {
		log.Errorf("Could not register protocols: %v", err)
		return nil, err
	}
	return s, nil
}
