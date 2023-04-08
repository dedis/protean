package main

import (
	"github.com/BurntSushi/toml"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/experiments/commons"
	"github.com/dedis/protean/experiments/microbenchmarks/sign/service"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	execbase "github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/libstate"
	statebase "github.com/dedis/protean/libstate/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
)

type SimulationService struct {
	onet.SimulationBFTree
	ContractFile string
	FSMFile      string
	DFUFile      string
	BlockTime    int
	NumOutput    int
	Size         int

	// internal structs
	byzID        skipchain.SkipBlockID
	stRoster     *onet.Roster
	execRoster   *onet.Roster
	signerRoster *onet.Roster
	stCl         *libstate.Client
	execCl       *libexec.Client

	threshMap   map[string]int
	rdata       *execbase.ByzData
	CID         byzcoin.InstanceID
	contractGen *skipchain.SkipBlock
}

func init() {
	onet.SimulationRegister("SignMicrobenchmark", NewMicrobenchmark)
}

func NewMicrobenchmark(config string) (onet.Simulation, error) {
	ss := &SimulationService{}
	_, err := toml.Decode(config, ss)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

func (s *SimulationService) Setup(dir string,
	hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (s *SimulationService) Node(config *onet.SimulationConfig) error {
	index, _ := config.Roster.Search(config.Server.ServerIdentity.GetID())
	if index < 0 {
		log.Fatal("Didn't find this node in roster")
	}
	log.Lvl3("Initializing node-index", index)
	return s.SimulationBFTree.Node(config)
}

func (s *SimulationService) initDFUs() error {
	s.execCl = libexec.NewClient(s.execRoster)
	_, err := s.execCl.InitUnit(s.threshMap[execbase.UID])
	if err != nil {
		log.Errorf("initializing execution unit: %v", err)
		return err
	}
	// Setup the state unit
	s.byzID, err = commons.SetupStateUnit(s.stRoster, s.BlockTime)
	if err != nil {
		log.Error(err)
	}
	return err
}

func (s *SimulationService) initContract() error {
	contract, err := libclient.ReadContractJSON(&s.ContractFile)
	if err != nil {
		log.Error(err)
		return err
	}
	fsm, err := libclient.ReadFSMJSON(&s.FSMFile)
	if err != nil {
		log.Error(err)
		return err
	}
	raw := &core.ContractRaw{
		Contract: contract,
		FSM:      fsm,
	}
	hdr := &core.ContractHeader{
		CodeHash:  utils.GetCodeHash(),
		Lock:      false,
		CurrState: fsm.InitialState,
	}
	reply, err := s.stCl.InitContract(raw, hdr, nil, 5)
	if err != nil {
		log.Error(err)
		return err
	}
	s.CID = reply.CID
	s.contractGen, err = s.stCl.FetchGenesisBlock(reply.TxResp.Proof.
		Latest.SkipChainID())
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (s *SimulationService) executeSign(config *onet.SimulationConfig) error {
	execCl := libexec.NewClient(s.execRoster)
	stCl := libstate.NewClient(byzcoin.NewClient(s.byzID, *s.stRoster))
	defer execCl.Close()
	defer stCl.Close()
	// Get state
	gcs, err := stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return err
	}
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}
	itReply, err := execCl.InitTransaction(s.rdata, cdata, "signwf", "sign")
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}

	// Get signer service
	outputData := commons.PrepareData(s.NumOutput, s.Size)
	signer := config.GetService(service.ServiceName).(*service.Signer)

	for round := 0; round < s.Rounds; round++ {
		signMonitor := monitor.NewTimeMeasure("sign")
		req := service.SignRequest{
			Roster:     s.signerRoster,
			OutputData: outputData,
			ExecReq:    execReq,
		}
		_, err = signer.Sign(&req)
		if err != nil {
			log.Error(err)
		}
		signMonitor.Record()
	}
	return err
}

func (s *SimulationService) runMicrobenchmark(config *onet.SimulationConfig) error {
	err := s.initDFUs()
	if err != nil {
		return err
	}
	// Initialize contract
	s.stCl = libstate.NewClient(byzcoin.NewClient(s.byzID, *s.stRoster))
	err = s.initContract()
	if err != nil {
		return err
	}
	err = s.executeSign(config)
	return nil
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	regRoster := onet.NewRoster(config.Roster.List[0:4])
	s.stRoster = onet.NewRoster(config.Roster.List[0:4])
	s.execRoster = onet.NewRoster(config.Roster.List[0:4])
	s.signerRoster = onet.NewRoster(config.Roster.List[4:])
	s.signerRoster.List[0] = config.Roster.List[0]

	keyMap := make(map[string][]kyber.Point)
	keyMap[service.UID] = s.signerRoster.ServicePublics(service.ServiceName)
	keyMap[statebase.UID] = s.stRoster.ServicePublics(skipchain.ServiceName)
	keyMap[execbase.UID] = s.execRoster.ServicePublics(libexec.ServiceName)
	s.rdata, s.threshMap, err = commons.SetupRegistry(regRoster, &s.DFUFile,
		keyMap, s.BlockTime)
	if err != nil {
		log.Error(err)
	}
	err = s.runMicrobenchmark(config)
	return err
}
