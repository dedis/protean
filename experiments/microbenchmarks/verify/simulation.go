package main

import (
	"crypto/rand"
	"fmt"
	"go.dedis.ch/cothority/v3/blscosi"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/experiments/commons"
	signsvc "github.com/dedis/protean/experiments/microbenchmarks/sign/service"
	verifysvc "github.com/dedis/protean/experiments/microbenchmarks/verify/service"
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
	"golang.org/x/xerrors"
)

type SimulationService struct {
	onet.SimulationBFTree
	DepType      string
	ContractFile string
	FSMFile      string
	DFUFile      string
	BlockTime    int
	NumInput     int
	NumBlocks    int
	Size         int

	// internal structs
	byzID          skipchain.SkipBlockID
	stRoster       *onet.Roster
	execRoster     *onet.Roster
	signerRoster   *onet.Roster
	verifierRoster *onet.Roster
	stCl           *libstate.Client
	execCl         *libexec.Client

	threshMap   map[string]int
	rdata       *execbase.ByzData
	CID         byzcoin.InstanceID
	contractGen *skipchain.SkipBlock
}

func init() {
	onet.SimulationRegister("VerifyMicrobenchmark", NewMicrobenchmark)
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
	time.Sleep(time.Duration(s.BlockTime/2) * time.Second)
	return nil
}

func (s *SimulationService) executeVerifyOpc(config *onet.SimulationConfig) error {
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
	itReply, err := execCl.InitTransaction(s.rdata, cdata, "verifywf", "verify")
	if err != nil {
		log.Error(err)
		return err
	}
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}

	// Get signer service
	outputData := commons.PrepareData(s.NumInput, s.Size)
	for k, _ := range outputData {
		fmt.Println(k)
	}
	signer := config.GetService(signsvc.ServiceName).(*signsvc.Signer)
	signReq := signsvc.SignRequest{
		Roster:     s.signerRoster,
		OutputData: outputData,
		ExecReq:    execReq,
	}
	signReply, err := signer.Sign(&signReq)
	if err != nil {
		log.Error(err)
	}
	// Get verifier service
	execReq.Index = 1
	execReq.OpReceipts = signReply.Receipts
	verifier := config.GetService(verifysvc.ServiceName).(*verifysvc.Verifier)

	for round := 0; round < s.Rounds; round++ {
		vMonitor := monitor.NewTimeMeasure("verify_opc")
		verifyReq := verifysvc.VerifyRequest{
			Roster:    s.verifierRoster,
			InputData: outputData,
			ExecReq:   execReq,
		}
		_, err = verifier.Verify(&verifyReq)
		if err != nil {
			log.Error(err)
		}
		vMonitor.Record()
	}
	return err
}

func (s *SimulationService) executeVerifyKv(config *onet.SimulationConfig) error {
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

	itReply, err := execCl.InitTransaction(s.rdata, cdata, "verifywf", "verify")
	if err != nil {
		log.Error(err)
		return err
	}
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}

	verifier := config.GetService(verifysvc.ServiceName).(*verifysvc.Verifier)
	sp := commons.PrepareStateProof(s.NumInput, gcs.Proof.Proof, s.contractGen)

	for round := 0; round < s.Rounds; round++ {
		vMonitor := monitor.NewTimeMeasure("verify_kv")
		verifyReq := verifysvc.VerifyRequest{
			Roster:      s.verifierRoster,
			StateProofs: sp,
			ExecReq:     execReq,
		}
		_, err = verifier.Verify(&verifyReq)
		if err != nil {
			log.Error(err)
		}
		vMonitor.Record()
	}
	return err
}

func (s *SimulationService) generateBlocks() error {
	buf := make([]byte, 128)
	for i := 0; i < s.NumBlocks; i++ {
		rand.Read(buf)
		args := byzcoin.Arguments{{Name: "test_key", Value: buf}}
		_, err := s.stCl.DummyUpdate(s.CID, args, 5)
		if err != nil {
			log.Error(err)
			return err
		}
		log.Info("Added block:", i)
	}
	return nil
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
	if s.DepType == "OPC" {
		err = s.executeVerifyOpc(config)
	} else {
		err = s.generateBlocks()
		if err != nil {
			return err
		}
		err = s.executeVerifyKv(config)
	}
	return err
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	keyMap := make(map[string][]kyber.Point)
	regRoster := onet.NewRoster(config.Roster.List[0:4])
	if s.DepType == "OPC" {
		s.stRoster = onet.NewRoster(config.Roster.List[0:4])
		s.execRoster = onet.NewRoster(config.Roster.List[0:4])
		s.signerRoster = onet.NewRoster(config.Roster.List[0:19])
		s.verifierRoster = onet.NewRoster(config.Roster.List[19:])
		s.verifierRoster.List[0] = config.Roster.List[0]
		log.Info("Registry roster size:", len(regRoster.List))
		log.Info("State roster size:", len(s.stRoster.List))
		log.Info("Exec roster size:", len(s.execRoster.List))
		log.Info("Signer roster size:", len(s.signerRoster.List))
		log.Info("Verifier roster size:", len(s.verifierRoster.List))
	} else if s.DepType == "KV" {
		s.execRoster = onet.NewRoster(config.Roster.List[0:4])
		s.signerRoster = onet.NewRoster(config.Roster.List[0:4])
		s.stRoster = onet.NewRoster(config.Roster.List[0:19])
		s.verifierRoster = onet.NewRoster(config.Roster.List[19:])
		s.verifierRoster.List[0] = config.Roster.List[0]
		log.Info("Registry roster size:", len(regRoster.List))
		log.Info("Signer roster size:", len(s.signerRoster.List))
		log.Info("Exec roster size:", len(s.execRoster.List))
		log.Info("State roster size:", len(s.stRoster.List))
		log.Info("Verifier roster size:", len(s.verifierRoster.List))
	} else {
		return xerrors.New("invalid dep type")
	}

	keyMap[statebase.UID] = s.stRoster.ServicePublics(skipchain.ServiceName)
	keyMap[execbase.UID] = s.execRoster.ServicePublics(libexec.ServiceName)
	keyMap[verifysvc.UID] = s.verifierRoster.ServicePublics(verifysvc.ServiceName)
	keyMap[signsvc.UID] = s.signerRoster.ServicePublics(blscosi.ServiceName)

	s.rdata, s.threshMap, err = commons.SetupRegistry(regRoster, &s.DFUFile,
		keyMap, s.BlockTime)
	if err != nil {
		log.Error(err)
		return err
	}
	err = s.runMicrobenchmark(config)
	log.Info("Simulation finished")
	return err
}
