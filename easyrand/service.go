package easyrand

import (
	"bytes"
	"encoding/binary"
	"github.com/dedis/protean/easyrand/base"
	"github.com/dedis/protean/easyrand/protocol"
	protean "github.com/dedis/protean/utils"
	"golang.org/x/xerrors"
	"time"

	"go.dedis.ch/cothority/v3/blscosi"
	dkgprotocol "go.dedis.ch/cothority/v3/dkg/pedersen"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	dkg "go.dedis.ch/kyber/v3/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v3/share/vss/pedersen"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

var easyrandID onet.ServiceID
var suite = bn256.NewSuite()
var vssSuite = suite.G2().(vss.Suite)

const dkgTimeout = 5 * time.Minute
const randTimeout = 5 * time.Minute
const genesisMsg = "genesis_msg"
const ServiceName = "EasyrandService"

func init() {
	var err error
	easyrandID, err = onet.RegisterNewService(ServiceName, newService)
	if err != nil {
		panic(err)
	}
}

// EasyRand holds the internal state of the service.
type EasyRand struct {
	*onet.ServiceProcessor
	roster     *onet.Roster
	threshold  int
	blsService *blscosi.Service

	keypair      *key.Pair
	distKeyStore *dkg.DistKeyShare
	pubPoly      *share.PubPoly
	blocks       [][]byte
}

func (s *EasyRand) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	s.roster = req.Roster
	s.threshold = req.Threshold
	return &InitUnitReply{}, nil
}

// InitDKG starts the DKG protocol.
func (s *EasyRand) InitDKG(req *InitDKGRequest) (*InitDKGReply, error) {
	// Run DKG
	tree := s.roster.GenerateStar()
	pi, err := s.CreateProtocol(protocol.DKGProtoName, tree)
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
	case <-time.After(dkgTimeout):
		log.Errorf("DKG did not finish")
		return nil, xerrors.New("dkg did not finish")
	}
	return &InitDKGReply{Public: s.pubPoly.Commit()}, nil
}

// CreateRandomness generates a new public randomness.
func (s *EasyRand) CreateRandomness(req *CreateRandomnessRequest) (*CreateRandomnessReply, error) {
	// Generate randomness
	nodeCount := len(s.roster.List)
	tree := s.roster.GenerateNaryTreeWithRoot(nodeCount-1, s.ServerIdentity())
	pi, err := s.CreateProtocol(protocol.SignProtoName, tree)
	if err != nil {
		log.Errorf("Create protocol error: %v", err)
		return nil, err
	}
	signPi := pi.(*protocol.SignProtocol)
	signPi.Msg = createNextMsg(s.blocks)
	signPi.Threshold = s.threshold
	err = signPi.Start()
	if err != nil {
		log.Errorf("Start protocol error: %v", err)
		return nil, err
	}
	select {
	case sig := <-signPi.FinalSignature:
		s.blocks = append(s.blocks, sig)
		return &CreateRandomnessReply{}, nil
	case <-time.After(randTimeout):
		log.Errorf("Timed out waiting for the final signature")
		return nil, xerrors.New("timeout waiting for final signature")
	}
}

func (s *EasyRand) GetRandomness(req *GetRandomnessRequest) (*GetRandomnessReply, error) {
	if req.Input.Round > uint64(len(s.blocks)-1) {
		return nil, xerrors.Errorf("round %d has not been reached yet",
			req.Input.Round)
	}
	round := req.Input.Round
	rBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(rBuf, round)

	nodeCount := len(s.roster.List)
	//threshold := nodeCount - (nodeCount-1)/3
	tree := s.roster.GenerateNaryTreeWithRoot(nodeCount-1, s.ServerIdentity())
	pi, err := s.CreateProtocol(protocol.VerifyProtoName, tree)
	if err != nil {
		log.Errorf("Create protocol error: %v", err)
		return nil, err
	}
	verifyPi := pi.(*protocol.RandomnessVerify)
	verifyPi.Threshold = s.threshold
	verifyPi.InputHashes, err = req.Input.PrepareHashes()
	if err != nil {
		log.Errorf("failed to prepare the input hashes: %v", err)
		return nil, err
	}
	verifyPi.Input = &req.Input
	verifyPi.ExecReq = &req.ExecReq
	prev := s.getRoundBlock(round)
	randOutput := base.RandomnessOutput{Public: s.pubPoly.Commit(),
		Round: round, Prev: prev, Value: s.blocks[round]}
	verifyPi.RandOutput = &randOutput
	verifyPi.KP = protean.GetBLSKeyPair(s.ServerIdentity())
	err = verifyPi.SetConfig(&onet.GenericConfig{Data: rBuf})
	if err != nil {
		return nil, xerrors.Errorf(
			"failed to set config for verify protocol: %v", err)
	}
	err = verifyPi.Start()
	if err != nil {
		return nil, xerrors.Errorf("Failed to start the verification protocol: " + err.Error())
	}
	if !<-verifyPi.Verified {
		return nil, xerrors.New("randomness verify failed")
	}
	return &GetRandomnessReply{Output: randOutput, Receipts: verifyPi.Receipts}, nil
}

func (s *EasyRand) getRoundBlock(round uint64) []byte {
	if round == 0 {
		return []byte(genesisMsg)
	}
	rBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(rBuf, round)
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

func (s *EasyRand) verifyRoundMsg(msg []byte, round uint64) error {
	if !bytes.Equal(msg, createNextMsg(s.blocks)) {
		return xerrors.New("bad message")
	}
	if uint64(len(s.blocks)) != round {
		return xerrors.Errorf("round values do not match: expected %d"+
			" received %d", uint64(len(s.blocks)), round)
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
	case protocol.DKGProtoName:
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
	case protocol.SignProtoName:
		pi, err := protocol.NewSignProtocol(tn, s.distKeyStore.PriShare(), s.pubPoly, suite)
		if err != nil {
			log.Errorf("Cannot initialize the signing protocol: %v", err)
			return nil, err
		}
		signProto := pi.(*protocol.SignProtocol)
		signProto.Threshold = s.threshold
		go func() {
			select {
			case sig := <-signProto.FinalSignature:
				s.blocks = append(s.blocks, sig)
			case <-time.After(5 * time.Minute):
				log.Errorf("%s time out while waiting for signature", s.ServerIdentity())
			}
		}()
		return pi, nil
	case protocol.VerifyProtoName:
		round := binary.LittleEndian.Uint64(conf.Data)
		if round > uint64(len(s.blocks)-1) {
			return nil, xerrors.Errorf("round %d has not been reached yet",
				round)
		}
		prev := s.getRoundBlock(round)
		value := s.blocks[round]
		pi, err := protocol.NewRandomnessVerify(tn)
		if err != nil {
			return nil, err
		}
		proto := pi.(*protocol.RandomnessVerify)
		proto.RandOutput = &base.RandomnessOutput{Public: s.pubPoly.Commit(), Round: round,
			Prev: prev, Value: value}
		proto.KP = protean.GetBLSKeyPair(s.ServerIdentity())
		return proto, nil
	default:
		return nil, nil
	}
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &EasyRand{
		ServiceProcessor: onet.NewServiceProcessor(c),
		keypair:          key.NewKeyPair(vssSuite),
		blsService:       c.Service(blscosi.ServiceName).(*blscosi.Service),
	}
	_, err := s.ProtocolRegister(protocol.DKGProtoName, func(n *onet.TreeNodeInstance) (
		onet.ProtocolInstance, error) {
		return dkgprotocol.CustomSetup(n, vssSuite, s.keypair)
	})
	if err != nil {
		log.Errorf("Registering protocol %s failed: %v", protocol.DKGProtoName, err)
		return nil, err
	}
	_, err = s.ProtocolRegister(protocol.SignProtoName, func(n *onet.TreeNodeInstance) (
		onet.ProtocolInstance, error) {
		// TODO giving NewSignProtocol to pointers isn't so nice because these mutate
		return protocol.NewSignProtocol(n, s.distKeyStore.PriShare(), s.pubPoly, suite)
	})
	if err != nil {
		log.Errorf("Registering protocol %s failed: %v", protocol.SignProtoName, err)
		return nil, err
	}
	err = s.RegisterHandlers(s.InitUnit, s.InitDKG, s.CreateRandomness, s.GetRandomness)
	if err != nil {
		log.Errorf("Registering handlers failed: %v", err)
		return nil, err
	}
	return s, nil
}
