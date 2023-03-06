package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/experiments/commons"
	signsvc "github.com/dedis/protean/experiments/microbenchmarks/sign/service"
	verifysvc "github.com/dedis/protean/experiments/microbenchmarks/verify/service"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	execbase "github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/libstate"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"time"
)

type SimulationService struct {
	onet.SimulationBFTree
	DepType      string
	ContractFile string
	FSMFile      string
	DFUFile      string
	BlockTime    int
	NumInput     int
	Size         int

	// internal structs
	byzID          skipchain.SkipBlockID
	stRoster       *onet.Roster
	execRoster     *onet.Roster
	signerRoster   *onet.Roster
	verifierRoster *onet.Roster
	stCl           *libstate.Client
	execCl         *libexec.Client

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
	_, err := s.execCl.InitUnit()
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
	reply, err := s.stCl.InitContract(raw, hdr, nil, 10)
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
	execReq := &core.ExecutionRequest{
		Index: 2,
		EP:    &itReply.Plan,
	}

	// Get signer service
	outputData := commons.PrepareData(s.NumInput, s.Size)
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
	execReq.Index = 3
	execReq.OpReceipts = signReply.Receipts
	verifier := config.GetService(verifysvc.ServiceName).(*verifysvc.Verifier)
	verReq := verifysvc.VerifyRequest{
		Roster:    s.verifierRoster,
		InputData: outputData,
		ExecReq:   execReq,
	}
	verReply, err := verifier.Verify(&verReq)
	if err != nil {
		log.Error(err)
	}
	fmt.Println(verReply)
	return err
}

func (s *SimulationService) executeVerifyKv(config *onet.SimulationConfig) error {

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
		err = s.executeVerifyKv(config)
	}
	return nil
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	regRoster := onet.NewRoster(config.Roster.List[0:4])
	if s.DepType == "OPC" {
		s.stRoster = config.Roster
		s.execRoster = config.Roster
		s.signerRoster = config.Roster
		s.verifierRoster = config.Roster

		keyMap := make(map[string][]kyber.Point)
		//keyMap["verifier"] = config.Roster.ServicePublics(blscosi.ServiceName)
		keyMap["verifier"] = config.Roster.ServicePublics(verifysvc.ServiceName)
		keyMap["signer"] = config.Roster.ServicePublics(blscosi.ServiceName)
		keyMap["state"] = config.Roster.ServicePublics(skipchain.ServiceName)
		keyMap["codeexec"] = config.Roster.ServicePublics(libexec.ServiceName)
		s.rdata, err = commons.SetupRegistry(regRoster, &s.DFUFile, keyMap)
		if err != nil {
			log.Error(err)
			return err
		}
	} else if s.DepType == "KV" {
		s.stRoster = config.Roster
		s.execRoster = config.Roster
		s.signerRoster = config.Roster
		s.verifierRoster = config.Roster

		keyMap := make(map[string][]kyber.Point)
		keyMap["verifier"] = config.Roster.ServicePublics(verifysvc.ServiceName)
		keyMap["signer"] = config.Roster.ServicePublics(blscosi.ServiceName)
		keyMap["state"] = config.Roster.ServicePublics(skipchain.ServiceName)
		keyMap["codeexec"] = config.Roster.ServicePublics(libexec.ServiceName)
		s.rdata, err = commons.SetupRegistry(regRoster, &s.DFUFile, keyMap)
		if err != nil {
			log.Error(err)
			return err
		}
	} else {
		return xerrors.New("invalid dep type")
	}
	err = s.runMicrobenchmark(config)
	return err
}
