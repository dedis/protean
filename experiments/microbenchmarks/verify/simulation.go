package main

import (
	"crypto/rand"
	"fmt"
	statebase "github.com/dedis/protean/libstate/base"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3"
	"golang.org/x/xerrors"
	"strconv"
	"strings"
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
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
)

type SimulationService struct {
	onet.SimulationBFTree
	DepType      string
	ContractFile string
	FSMFile      string
	DFUFile      string
	BlockTime    int

	// verify_opc structs
	NumInputs int
	Size      int

	// verify_kv structs
	NumInputsStr string
	NumBlocksStr string
	NumInputsKV  []int
	NumBlocks    []int
	latestProof  map[int]*byzcoin.GetProofResponse

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
	outputData := commons.PrepareData(s.NumInputs, s.Size)
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

	var err error
	verifier := config.GetService(verifysvc.ServiceName).(*verifysvc.Verifier)
	
	for _, ni := range s.NumInputsKV {
		for _, nb := range s.NumBlocks {
			pr := &s.latestProof[nb].Proof
			sp := commons.PrepareStateProof(ni, pr, s.contractGen)
			cdata := &execbase.ByzData{IID: s.CID, Proof: pr, Genesis: s.contractGen}
			txnName := fmt.Sprintf("verify_%d", ni)
			itReply, err := execCl.InitTransaction(s.rdata, cdata, "verifywf", txnName)
			if err != nil {
				log.Error(err)
				return err
			}
			execReq := &core.ExecutionRequest{Index: 0, EP: &itReply.Plan}
			for round := 0; round < s.Rounds; round++ {
				vMonitor := monitor.NewTimeMeasure(fmt.Sprintf("verify_%d_%d",
					ni, nb))
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
		}
	}
	return err
}

func (s *SimulationService) generateBlocks() error {
	idx := 0
	buf := make([]byte, 128)
	blkCount := s.NumBlocks[len(s.NumBlocks)-1]
	for i := 1; i <= blkCount; i++ {
		rand.Read(buf)
		args := byzcoin.Arguments{{Name: "test_key", Value: buf}}
		_, err := s.stCl.DummyUpdate(s.CID, args, 5)
		if err != nil {
			log.Error(err)
			return err
		}
		if i == s.NumBlocks[idx] {
			time.Sleep(5 * time.Second)
			latestProof, err := s.stCl.DummyGetProof(s.CID)
			if err != nil {
				log.Error(err)
				return err
			}
			s.latestProof[i] = latestProof
			idx++
			log.Infof("Added block: %d - idx: %d - link#: %d", i, latestProof.Proof.Latest.Index, len(latestProof.Proof.Links))
		}
	}
	return nil
}

func (s *SimulationService) stringSliceToIntSlice() {
	numInputsSlice := strings.Split(s.NumInputsStr, ";")
	for _, n := range numInputsSlice {
		numInput, _ := strconv.Atoi(n)
		s.NumInputsKV = append(s.NumInputsKV, numInput)
	}
	numBlocksSlice := strings.Split(s.NumBlocksStr, ";")
	for _, n := range numBlocksSlice {
		numBlocks, _ := strconv.Atoi(n)
		s.NumBlocks = append(s.NumBlocks, numBlocks)
	}
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
		s.stringSliceToIntSlice()
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
	s.latestProof = make(map[int]*byzcoin.GetProofResponse)
	s.execRoster = onet.NewRoster(config.Roster.List[0:4])
	s.verifierRoster = onet.NewRoster(config.Roster.List[19:])
	s.verifierRoster.List[0] = config.Roster.List[0]
	regRoster := onet.NewRoster(config.Roster.List[0:4])

	if s.DepType == "OPC" {
		s.stRoster = onet.NewRoster(config.Roster.List[0:4])
		s.signerRoster = onet.NewRoster(config.Roster.List[0:19])
	} else if s.DepType == "KV" {
		s.signerRoster = onet.NewRoster(config.Roster.List[0:4])
		s.stRoster = onet.NewRoster(config.Roster.List[0:19])
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
