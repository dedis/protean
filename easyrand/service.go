package easyrand

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"github.com/dedis/protean/verify"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
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

	// Timeout waiting for final signtaure
	timeout      time.Duration
	keypair      *key.Pair
	distKeyStore *dkg.DistKeyShare
	pubPoly      *share.PubPoly

	blocks [][]byte
}

func (s *EasyRand) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	cfg := req.Cfg
	//genesisReply, err := utils.CreateGenesisBlock(s.scService, req.ScData, req.Roster)
	genesisReply, err := utils.CreateGenesisBlock(s.scService, cfg.ScCfg, cfg.Roster)
	if err != nil {
		log.Errorf("Cannot create the skipchain genesis block: %v", err)
		return nil, err
	}
	s.genesis = genesisReply.Latest.Hash
	//s.roster = req.Roster
	s.roster = cfg.Roster
	s.timeout = req.Timeout
	///////////////////////
	// Now adding a block with the unit information
	//enc, err := protobuf.Encode(req.BaseStore)
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

// InitDKG starts the DKG protocol.
func (s *EasyRand) InitDKG(req *InitDKGRequest) (*InitDKGReply, error) {
	tree := s.roster.GenerateStar()
	pi, err := s.CreateProtocol(dkgProtoName, tree)
	if err != nil {
		log.Errorf("Create protocol error: %v", err)
		return nil, err
	}
	setup := pi.(*dkgprotocol.Setup)
	setup.Wait = true

	err = pi.Start()
	if err != nil {
		log.Errorf("Start protocol error: %v", err)
		return nil, err
	}

	select {
	case <-setup.Finished:
		err := s.storeShare(setup)
		if err != nil {
			log.Errorf("Storing DKG shares failed: %v", err)
			return nil, err
		}
	// Timeout was originally 5 seconds
	case <-time.After(time.Duration(req.Timeout) * time.Second):
		log.Errorf("DKG did not finish")
		return nil, errors.New("dkg did not finish")
	}
	//return &InitDKGReply{}, nil
	return &InitDKGReply{Public: s.pubPoly.Commit()}, nil
}

// Randomness returns the public randomness.
func (s *EasyRand) Randomness(req *RandomnessRequest) (*RandomnessReply, error) {
	// First verify the execution request
	db := s.scService.GetDB()
	blk, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Cannot get the latest block: %v", err)
		return nil, err
	}
	verified := s.verifyExecutionRequest(RAND, blk, req.ExecData)
	if !verified {
		log.Errorf("Cannot verify execution plan")
		return nil, fmt.Errorf("Cannot verify execution plan")
	}
	// Generate randomness
	pi, err := s.CreateProtocol(signProtoName, s.roster.GenerateStar())
	if err != nil {
		log.Errorf("Create protocol error: %v", err)
		return nil, err
	}
	signPi := pi.(*SignProtocol)
	signPi.Msg = createNextMsg(s.blocks)
	err = pi.Start()
	if err != nil {
		log.Errorf("Start protocol error: %v", err)
		return nil, err
	}
	select {
	case sig := <-signPi.FinalSignature:
		s.blocks = append(s.blocks, sig)
		round := uint64(len(s.blocks) - 1)
		prev := s.getRoundBlock(round)
		// Collectively sign the execution plan
		blsSig, err := s.signExecutionPlan(req.ExecData.ExecPlan)
		if err != nil {
			log.Errorf("Cannot produce blscosi signature: %v", err)
			return nil, err
		}
		return &RandomnessReply{Round: round, Prev: prev, Value: sig, Sig: blsSig}, nil
	// s.timeout was originally 2 seconds
	case <-time.After(s.timeout * time.Second):
		log.Errorf("Timed out waiting for the final signature")
		return nil, errors.New("timeout waiting for final signature")
	}
}

func (s *EasyRand) verifyExecutionRequest(txnName string, blk *skipchain.SkipBlock, execData *sys.ExecutionData) bool {
	tree := s.roster.GenerateNaryTreeWithRoot(len(s.roster.List), s.ServerIdentity())
	pi, err := s.CreateProtocol(verify.Name, tree)
	if err != nil {
		log.Errorf("Cannot create protocol: %v", err)
		return false
	}
	verifyProto := pi.(*verify.VP)
	verifyProto.Index = execData.Index
	verifyProto.TxnName = txnName
	verifyProto.Block = blk
	verifyProto.ExecPlan = execData.ExecPlan
	verifyProto.ClientSigs = execData.ClientSigs
	verifyProto.CompilerSig = execData.CompilerSig
	verifyProto.UnitSigs = execData.UnitSigs
	err = verifyProto.Start()
	if err != nil {
		log.Errorf("Cannot start protocol: %v", err)
		return false
	}
	if !<-verifyProto.Verified {
		return false
	} else {
		return true
	}
}

func (s *EasyRand) signExecutionPlan(ep *sys.ExecutionPlan) (protocol.BlsSignature, error) {
	epHash, err := utils.ComputeEPHash(ep)
	if err != nil {
		log.Errorf("Cannot compute the execution plan hash: %v", err)
		return nil, err
	}
	cosiResp, err := utils.BlsCosiSign(s.cosiService, s.roster, epHash)
	if err != nil {
		log.Errorf("Cannot produce blscosi signature: %v", err)
		return nil, err
	}
	return cosiResp.(*blscosi.SignatureResponse).Signature, nil
}

func (s *EasyRand) getRoundBlock(round uint64) []byte {
	if round > uint64(len(s.blocks)) {
		return nil
	}
	if round == 0 {
		return []byte(genesisMsg)
	}
	rBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(rBuf, uint64(round))
	buf := append(rBuf, s.blocks[round-1]...)
	return buf
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

// NewProtocol is a callback for creating protocols on non-root nodes.
func (s *EasyRand) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3(s.ServerIdentity(), tn.ProtocolName(), conf)
	switch tn.ProtocolName() {
	case dkgProtoName:
		pi, err := dkgprotocol.CustomSetup(tn, vssSuite, s.keypair)
		if err != nil {
			log.Errorf("DKG protocol custom setup failed: %v", err)
			return nil, err
		}
		setup := pi.(*dkgprotocol.Setup)

		go func() {
			<-setup.Finished
			err := s.storeShare(setup)
			if err != nil {
				log.Errorf("%s failed while storing DKG shares: %v", s.ServerIdentity(), err)
			}
		}()
		return pi, nil
	case signProtoName:
		pi, err := NewSignProtocol(tn, s.verify, s.distKeyStore.PriShare(), s.pubPoly, suite)
		if err != nil {
			log.Errorf("Cannot initialize the signing protocol: %v", err)
			return nil, err
		}
		signProto := pi.(*SignProtocol)

		go func() {
			select {
			case sig := <-signProto.FinalSignature:
				s.blocks = append(s.blocks, sig)
			case <-time.After(time.Second):
				log.Errorf("%s time out while waiting for signature", s.ServerIdentity())
			}
		}()

		return pi, nil
	default:
		return nil, errors.New("invalid protocol")
	}
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
