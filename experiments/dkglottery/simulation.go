package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/experiments/commons"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	"github.com/dedis/protean/libexec/apps/dkglottery"
	execbase "github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/libstate"
	"github.com/dedis/protean/threshold"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
	"go.dedis.ch/protobuf"
)

type SimulationService struct {
	onet.SimulationBFTree
	ContractFile    string
	FSMFile         string
	DFUFile         string
	BlockTime       int
	NumParticipants int
	NumSlots        int
	Seed            int

	// internal structs
	byzID        skipchain.SkipBlockID
	stRoster     *onet.Roster
	execRoster   *onet.Roster
	threshRoster *onet.Roster
	stCl         *libstate.Client
	execCl       *libexec.Client
	thCl         *threshold.Client

	rdata       *execbase.ByzData
	CID         byzcoin.InstanceID
	contractGen *skipchain.SkipBlock
	X           kyber.Point
}

func init() {
	onet.SimulationRegister("DKGLottery", NewDKGLotteryService)
}

func NewDKGLotteryService(config string) (onet.Simulation, error) {
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
	s.thCl = threshold.NewClient(s.threshRoster)
	_, err = s.thCl.InitUnit()
	if err != nil {
		log.Errorf("initializing threshold unit: %v", err)
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
	encTickets := dkglottery.EncTickets{}
	buf, err := protobuf.Encode(&encTickets)
	if err != nil {
		log.Error(err)
		return err
	}
	args := byzcoin.Arguments{{Name: "enc_tickets", Value: buf}}
	reply, err := s.stCl.InitContract(raw, hdr, args, 10)
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

func (s *SimulationService) executeSetup() error {
	gcs, err := s.stCl.GetState(s.CID)
	if err != nil {
		return err
	}
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}
	itReply, err := s.execCl.InitTransaction(s.rdata, cdata, "setupwf", "setup")
	if err != nil {
		log.Error(err)
		return err
	}
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	// Step 1: init_dkg
	dkgReply, err := s.thCl.InitDKG(execReq)
	if err != nil {
		log.Error(err)
		return err
	}
	// Step 2: exec
	setupInput := dkglottery.SetupInput{Pk: dkgReply.Output.X}
	data, err := protobuf.Encode(&setupInput)
	if err != nil {
		log.Error(err)
		return err
	}
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "setup_dkglot",
		Data:        data,
		StateProofs: sp,
	}
	execReq.Index = 1
	execReq.OpReceipts = dkgReply.Receipts
	execReply, err := s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Error(err)
		return err
	}
	// Step 3: update_state
	var setupOut dkglottery.SetupOutput
	err = protobuf.Decode(execReply.Output.Data, &setupOut)
	if err != nil {
		log.Error(err)
		return err
	}
	inReceipts := make(map[int]map[string]*core.OpcodeReceipt)
	inReceipts[execReq.Index] = execReply.InputReceipts
	execReq.Index = 2
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = s.stCl.UpdateState(setupOut.WS, execReq, inReceipts, 5)
	if err != nil {
		log.Error(err)
		return err
	}
	_, err = s.stCl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, s.BlockTime)
	if err != nil {
		log.Error(err)
	}
	s.X = dkgReply.Output.X
	return err
}

func (s *SimulationService) executeJoin(idx int) error {
	execCl := libexec.NewClient(s.execRoster)
	stCl := libstate.NewClient(byzcoin.NewClient(s.byzID, *s.stRoster))
	defer execCl.Close()
	defer stCl.Close()

	label := fmt.Sprintf("p%d_join", idx)
	joinMonitor := monitor.NewTimeMeasure(label)
	ticket := commons.GenerateTicket(s.X)
	gcs, err := stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return err
	}
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}
	input := dkglottery.JoinInput{
		Ticket: dkglottery.Ticket{
			Data: ticket,
		},
	}
	data, err := protobuf.Encode(&input)
	if err != nil {
		log.Errorf("encoding input: %v", err)
		return err
	}
	lastRoot := gcs.Proof.Proof.InclusionProof.GetRoot()
	done := false
	for !done {
		itReply, err := execCl.InitTransaction(s.rdata, cdata, "joinwf", "join")
		if err != nil {
			log.Errorf("initializing txn: %v", err)
			return err
		}
		// Step 1: execute
		sp := make(map[string]*core.StateProof)
		sp["readset"] = &gcs.Proof
		execInput := execbase.ExecuteInput{
			FnName:      "join_dkglot",
			Data:        data,
			StateProofs: sp,
		}
		execReq := &core.ExecutionRequest{
			Index: 0,
			EP:    &itReply.Plan,
		}
		execReply, err := execCl.Execute(execInput, execReq)
		if err != nil {
			log.Errorf("executing join_dkglot: %v", err)
			return err
		}
		// Step 2: update_state
		var joinOut dkglottery.JoinOutput
		err = protobuf.Decode(execReply.Output.Data, &joinOut)
		if err != nil {
			log.Errorf("decoding join output: %v", err)
			return err
		}
		execReq.Index = 1
		execReq.OpReceipts = execReply.OutputReceipts
		_, err = stCl.UpdateState(joinOut.WS, execReq, nil, 5)
		if err != nil {
			pr, err := stCl.WaitProof(s.CID[:], lastRoot, s.BlockTime)
			if err != nil {
				log.Errorf("wait proof: %v", err)
				return err
			}
			gcs.Proof.Proof = pr
			cdata.Proof = gcs.Proof.Proof
			lastRoot = pr.InclusionProof.GetRoot()
		} else {
			_, err := stCl.WaitProof(s.CID[:], lastRoot, s.BlockTime)
			if err != nil {
				log.Errorf("wait proof: %v", err)
				return err
			}
			done = true
		}
	}
	joinMonitor.Record()
	return nil
}

func (s *SimulationService) executeClose() error {
	// Get state
	gcs, err := s.stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return err
	}
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}

	// Initialize transaction
	itReply, err := s.execCl.InitTransaction(s.rdata, cdata, "closewf", "close")
	if err != nil {
		log.Errorf("initializing txn: %v", err)
		return err
	}
	// Step 1: exec
	closeInput := dkglottery.CloseInput{
		Barrier: 0,
	}
	data, err := protobuf.Encode(&closeInput)
	if err != nil {
		log.Errorf("encoding close input: %v", err)
		return err
	}
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "close_dkglot",
		Data:        data,
		StateProofs: sp,
	}
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	execReply, err := s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing close_dkglot: %v", err)
		return err
	}

	// Step 2: update_state
	var closeOut dkglottery.CloseOutput
	err = protobuf.Decode(execReply.Output.Data, &closeOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = s.stCl.UpdateState(closeOut.WS, execReq, nil, 5)
	if err != nil {
		log.Errorf("updating state: %v", err)
		return err
	}

	// Wait for proof
	_, err = s.stCl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, s.BlockTime)
	if err != nil {
		log.Errorf("wait proof: %v", err)
	}
	return err
}

func (s *SimulationService) executeFinalize() error {
	// Get state
	gcs, err := s.stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return err
	}
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}

	// Initialize transaction
	itReply, err := s.execCl.InitTransaction(s.rdata, cdata, "finalizewf",
		"finalize")
	if err != nil {
		log.Errorf("initializing txn: %v", err)
		return err
	}

	// Step 1: exec
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "prepare_decrypt_dkglot",
		StateProofs: sp,
	}
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	execReply, err := s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing prepare_decrypt_dkglot: %v", err)
		return err
	}

	// Step 2: decrypt
	var prepOut dkglottery.PrepDecOutput
	err = protobuf.Decode(execReply.Output.Data, &prepOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	decReply, err := s.thCl.Decrypt(&prepOut.Input, execReq)
	if err != nil {
		log.Errorf("decrypting: %v", err)
		return err
	}

	// Step 3: exec
	finalInput := dkglottery.FinalizeInput{Ps: decReply.Output.Ps}
	data, err := protobuf.Encode(&finalInput)
	if err != nil {
		log.Errorf("protobuf encode: %v", err)
		return err
	}
	execInput = execbase.ExecuteInput{
		FnName:      "finalize_dkglot",
		Data:        data,
		StateProofs: sp,
	}
	inReceipts := make(map[int]map[string]*core.OpcodeReceipt)
	inReceipts[execReq.Index] = decReply.InputReceipts
	execReq.Index = 2
	execReq.OpReceipts = decReply.OutputReceipts
	execReply, err = s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing finalize_dkglot: %v", err)
		return err
	}

	// Step 4: update_state
	var finalOut dkglottery.FinalizeOutput
	err = protobuf.Decode(execReply.Output.Data, &finalOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	inReceipts[execReq.Index] = execReply.InputReceipts
	execReq.Index = 3
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = s.stCl.UpdateState(finalOut.WS, execReq, inReceipts, 5)
	if err != nil {
		log.Errorf("updating state: %v", err)
		return err
	}

	// Wait for proof
	_, err = s.stCl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, s.BlockTime)
	if err != nil {
		log.Errorf("wait proof: %v", err)
	}
	return err
}

func (s *SimulationService) runDKGLottery() error {
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
	err = s.executeSetup()
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	//schedule := []int{0, 1, 0, 2, 1, 0, 1, 0, 2, 1, 0, 0, 1, 1, 0}
	schedule := commons.GenerateSchedule(s.Seed, s.NumParticipants, s.NumSlots)
	log.Info(schedule)
	var ongoing int64
	ctr := 0
	for i := 0; i < len(schedule); i++ {
		pCount := schedule[i]
		if pCount != 0 {
			wg.Add(pCount)
			for j := 0; j < pCount; j++ {
				go func(idx int) {
					defer wg.Done()
					atomic.AddInt64(&ongoing, 1)
					err = s.executeJoin(idx)
					atomic.AddInt64(&ongoing, -1)
				}(ctr)
				ctr++
			}
		} else {
			count := atomic.LoadInt64(&ongoing)
			if count == 0 {
				log.Infof("continue @ %d\n", i)
			}
		}
		time.Sleep(time.Duration(s.BlockTime) * time.Second)
	}
	wg.Wait()
	err = s.executeClose()
	if err != nil {
		return err
	}
	err = s.executeFinalize()
	return err
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	regRoster := onet.NewRoster(config.Roster.List[0:4])
	s.stRoster = onet.NewRoster(config.Roster.List[4:])
	s.execRoster = s.stRoster
	s.threshRoster = s.stRoster

	keyMap := make(map[string][]kyber.Point)
	keyMap["state"] = s.stRoster.ServicePublics(skipchain.ServiceName)
	keyMap["codeexec"] = s.execRoster.ServicePublics(libexec.ServiceName)
	keyMap["threshold"] = s.threshRoster.ServicePublics(blscosi.ServiceName)
	s.rdata, err = commons.SetupRegistry(regRoster, &s.DFUFile, keyMap)
	if err != nil {
		log.Error(err)
	}
	err = s.runDKGLottery()
	return err
}
