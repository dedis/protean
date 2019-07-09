package state

import (
	"crypto/sha256"
	"errors"
	"github.com/ceyhunalp/protean_code"
	"github.com/ceyhunalp/protean_code/verify"
	"go.dedis.ch/cothority/v3/blscosi"
	//"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

// This service is only used because we need to register our contracts to
// the ByzCoin service. So we create this stub and add contracts to it
// from the `contracts` directory.

var pairingSuite = suites.MustFind("bn256.Adapter").(*pairing.SuiteBn256)

var ServiceName = "StateService"
var stateID onet.ServiceID

const proteanSubFtCosi = "protean_sub_ftcosi"
const proteanFtCosi = "protean_ftcosi"

// Service is only used to being able to store our contracts
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	roster      *onet.Roster
	genesis     skipchain.SkipBlockID
	byzService  *byzcoin.Service
	cosiService *blscosi.Service
	scService   *skipchain.Service
}

func init() {
	var err error
	stateID, err = onet.RegisterNewService("stateService", newService)
	log.ErrFatal(err)
	network.RegisterMessages(&protean.InitUnitRequest{}, &SetKVRequest{}, &SetKVReply{}, &UpdateStateRequest{})
}

//func (s *Service) InitUnit(req *InitUnitRequest) error {
//s.unitID = req.UnitID
//s.txns = req.Txns
//return nil
//}

func (s *Service) CreateSkipchain(req *protean.CreateSkipchainRequest) (*protean.CreateSkipchainReply, error) {
	genesis := skipchain.NewSkipBlock()
	genesis.MaximumHeight = req.MHeight
	genesis.BaseHeight = req.BHeight
	genesis.Roster = req.Roster
	genesis.VerifierIDs = skipchain.VerificationStandard
	reply, err := s.scService.StoreSkipBlock(&skipchain.StoreSkipBlock{
		NewBlock: genesis,
	})
	if err != nil {
		return nil, err
	}
	//s.roster = req.Roster
	s.genesis = reply.Latest.Hash
	s.roster = req.Roster
	log.Info("In CreateSkipchain genesis is", reply.Latest.Hash)
	return &protean.CreateSkipchainReply{Genesis: reply.Latest.Hash}, nil
}

func (s *Service) InitUnit(req *protean.InitUnitRequest) error {
	enc, err := protobuf.Encode(&protean.UnitStorage{
		UnitID:   req.UnitID,
		Txns:     req.Txns,
		CompKeys: req.CompilerKeys,
	})
	if err != nil {
		log.Errorf("protobufEncode error: %v", err)
		return err
	}

	db := s.scService.GetDB()
	latest, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Couldn't find the latest block: %v", err)
		return err
	}
	block := latest.Copy()
	block.Data = enc
	block.GenesisID = block.SkipChainID()
	block.Index++
	_, err = s.scService.StoreSkipBlock(&skipchain.StoreSkipBlock{
		NewBlock:          block,
		TargetSkipChainID: latest.SkipChainID(),
	})
	if err != nil {
		log.Errorf("Couldn't store new skipblock: %v", err)
		return err
	}
	return nil
}

//TODO: Update state probably needs to return something more than an error.
//Maybe something about the state update? (e.g. proof?)
func (s *Service) UpdateState(req *UpdateStateRequest) error {
	// Before we send Byzcoin transactions to update state, we need to make
	// sure that the execution plan has the necesssary signatures
	db := s.scService.GetDB()
	blk, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Couldn't get the latest block: %v", err)
		return err
	}
	tree := s.roster.GenerateNaryTreeWithRoot(len(s.roster.List), s.ServerIdentity())
	pi, err := s.CreateProtocol(verify.Name, tree)
	if err != nil {
		log.Errorf("Creating protocol failed: %v", err)
		return err
	}
	verifyProto := pi.(*verify.VP)
	verifyProto.Block = blk
	verifyProto.Index = req.Index
	verifyProto.ExecPlan = req.ExecPlan
	verifyProto.PlanSig = req.PlanSig
	verifyProto.SigMap = req.SigMap
	//verifyProto.FaultThreshold = req.FaultThreshold

	if !<-verifyProto.Verified {
		log.Lvl2("Execution plan verification success!")
	} else {
		log.Errorf("Execution plan verification failed!")
		return errors.New("Execution plan verification failed!")
	}

	//Now you can do the actual FU-related stuff

	//Final step: collectively sign the execution plan
	payload, err := protobuf.Encode(req.ExecPlan)
	if err != nil {
		log.Errorf("protobuf encode failed: %v", err)
		return nil
	}
	h := sha256.New()
	h.Write(payload)

	return nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		cosiService:      c.Service(blscosi.ServiceName).(*blscosi.Service),
		byzService:       c.Service(byzcoin.ServiceName).(*byzcoin.Service),
		scService:        c.Service(skipchain.ServiceName).(*skipchain.Service),
	}
	if err := s.RegisterHandlers(s.CreateSkipchain, s.InitUnit, s.UpdateState); err != nil {
		return nil, errors.New("Could not register messages")
	}
	err := byzcoin.RegisterContract(c, ContractKeyValueID, contractValueFromBytes)
	if err != nil {
		return nil, err
	}
	//_, err = s.ProtocolRegister(proteanFtCosi, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	//return protocol.NewBlsCosi(n, s.verifyExecutionPlan, proteanSubFtCosi, pairingSuite)
	//})
	return s, nil
}
