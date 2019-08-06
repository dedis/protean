package easyrand

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi"
	dkgprotocol "go.dedis.ch/cothority/v3/dkg/pedersen"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	dkg "go.dedis.ch/kyber/v3/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v3/share/vss/pedersen"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

var serviceID onet.ServiceID
var suite = bn256.NewSuite()
var vssSuite = suite.G2().(vss.Suite)

const dkgProtoName = "easyrand_dkg"
const signProtoName = "easyrand_sign"
const genesisMsg = "genesis_msg"

const ServiceName = "EasyRandService"

func init() {
	var err error
	serviceID, err = onet.RegisterNewService(ServiceName, newService)
	if err != nil {
		panic(err)
	}
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{}, &InitDKGRequest{}, &InitDKGReply{}, &RandomnessRequest{}, &RandomnessReply{})
}

// EasyRand holds the internal state of the service.
type EasyRand struct {
	*onet.ServiceProcessor
	scService   *skipchain.Service
	cosiService *blscosi.Service
	roster      *onet.Roster
	genesis     skipchain.SkipBlockID

	keypair      *key.Pair
	distKeyStore *dkg.DistKeyShare
	pubPoly      *share.PubPoly

	blocks [][]byte
}

func (s *EasyRand) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	genesisReply, err := utils.CreateGenesisBlock(s.scService, req.ScData)
	if err != nil {
		log.Errorf("Cannot create the skipchain genesis block: %v", err)
		return nil, err
	}
	s.genesis = genesisReply.Latest.Hash
	s.roster = req.ScData.Roster
	///////////////////////
	// Now adding a block with the unit information
	enc, err := protobuf.Encode(req.BaseStore)
	if err != nil {
		log.Errorf("Error in protobuf encoding: %v", err)
		return nil, err
	}
	err = utils.StoreBlock(s.scService, s.genesis, enc)
	if err != nil {
		return nil, err
	}
	///////////////////////
	//InitDKG
	///////////////////////
	tree := s.roster.GenerateStar()
	pi, err := s.CreateProtocol(dkgProtoName, tree)
	if err != nil {
		return nil, err
	}
	setup := pi.(*dkgprotocol.Setup)
	setup.Wait = true
	if err := pi.Start(); err != nil {
		return nil, err
	}
	select {
	case <-setup.Finished:
		if err := s.storeShare(setup); err != nil {
			return nil, err
		}
	case <-time.After(5 * time.Second):
		return nil, errors.New("DKG did not finish")
	}
	return &InitUnitReply{Genesis: genesisReply.Latest.Hash}, nil
}

// InitDKG starts the DKG protocol.
//func (s *EasyRand) InitDKG(req *InitDKGRequest) (*InitDKGReply, error) {
//tree := req.Roster.GenerateStar()
//pi, err := s.CreateProtocol(dkgProtoName, tree)
//if err != nil {
//return nil, err
//}
//setup := pi.(*dkgprotocol.Setup)
//setup.Wait = true

//if err := pi.Start(); err != nil {
//return nil, err
//}

//select {
//case <-setup.Finished:
//if err := s.storeShare(setup); err != nil {
//return nil, err
//}
//case <-time.After(5 * time.Second):
//return nil, errors.New("dkg did not finish")
//}
//return &InitDKGReply{}, nil
//}

// Randomness returns the public randomness.
func (s *EasyRand) Randomness(req *RandomnessRequest) (*RandomnessReply, error) {
	pi, err := s.CreateProtocol(signProtoName, req.Roster.GenerateStar())
	if err != nil {
		return nil, err
	}
	signPi := pi.(*SignProtocol)
	signPi.Msg = createNextMsg(s.blocks)
	if err := pi.Start(); err != nil {
		return nil, err
	}

	select {
	case sig := <-signPi.FinalSignature:
		s.blocks = append(s.blocks, sig)
		return &RandomnessReply{uint64(len(s.blocks) - 1), sig}, nil
	case <-time.After(2 * time.Second):
		return nil, errors.New("timeout waiting for final signature")
	}
}

// NewProtocol is a callback for creating protocols on non-root nodes.
func (s *EasyRand) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3(s.ServerIdentity(), tn.ProtocolName(), conf)
	switch tn.ProtocolName() {
	case dkgProtoName:
		pi, err := dkgprotocol.CustomSetup(tn, vssSuite, s.keypair)
		if err != nil {
			return nil, err
		}
		setup := pi.(*dkgprotocol.Setup)

		go func() {
			<-setup.Finished
			if err := s.storeShare(setup); err != nil {
				log.Error(s.ServerIdentity(), err)
			}
		}()
		return pi, nil
	case signProtoName:
		pi, err := NewSignProtocol(tn, s.verify, s.distKeyStore.PriShare(), s.pubPoly, suite)
		if err != nil {
			return nil, err
		}
		signProto := pi.(*SignProtocol)

		go func() {
			select {
			case sig := <-signProto.FinalSignature:
				s.blocks = append(s.blocks, sig)
			case <-time.After(time.Second):
				log.Error(s.ServerIdentity(), "time out while waiting for signature")
			}
		}()

		return pi, nil
	default:
		return nil, errors.New("invalid protocol")
	}
}

func (s *EasyRand) storeShare(setup *dkgprotocol.Setup) error {
	_, dks, err := setup.SharedSecret()
	if err != nil {
		return err
	}
	s.distKeyStore = dks
	s.pubPoly = share.NewPubPoly(vssSuite, vssSuite.Point().Base(), dks.Commitments())
	return nil
}

func (s *EasyRand) verify(msg []byte) error {
	if !bytes.Equal(msg, createNextMsg(s.blocks)) {
		return errors.New("bad message")
	}
	return nil
}

func createNextMsg(blocks [][]byte) []byte {
	round := len(blocks)
	if round == 0 {
		return []byte(genesisMsg)
	}
	rBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(rBuf, uint64(round))
	buf := append(rBuf, blocks[len(blocks)-1]...)
	return buf
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &EasyRand{
		ServiceProcessor: onet.NewServiceProcessor(c),
		keypair:          key.NewKeyPair(vssSuite),
		scService:        c.Service(skipchain.ServiceName).(*skipchain.Service),
		cosiService:      c.Service(blscosi.ServiceName).(*blscosi.Service),
	}
	_, err := s.ProtocolRegister(dkgProtoName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return dkgprotocol.CustomSetup(n, vssSuite, s.keypair)
	})
	if err != nil {
		log.Errorf("Registering protocol %s failed: %v", dkgProtoName, err)
		return nil, err
	}
	_, err = s.ProtocolRegister(signProtoName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		// TODO giving NewSignProtocol to pointers isn't so nice because these mutate
		return NewSignProtocol(n, s.verify, s.distKeyStore.PriShare(), s.pubPoly, suite)
	})
	if err != nil {
		log.Errorf("Registering protocol %s failed: %v", signProtoName, err)
		return nil, err
	}
	err = s.RegisterHandlers(s.InitUnit, s.Randomness)
	if err != nil {
		log.Errorf("Registering handlers failed: %v", err)
		return nil, err
	}
	return s, nil
}
