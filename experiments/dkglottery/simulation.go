package main

import (
	"fmt"
	statebase "github.com/dedis/protean/libstate/base"
	thbase "github.com/dedis/protean/threshold/base"
	"go.dedis.ch/cothority/v3/blscosi"
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
	ContractFile      string
	BatchContractFile string
	FSMFile           string
	DFUFile           string
	ScheduleFile      string
	BlockTime         int
	NumParticipants   int
	Batched           bool
	BatchSize         int

	// internal structs
	byzID        skipchain.SkipBlockID
	stRoster     *onet.Roster
	execRoster   *onet.Roster
	threshRoster *onet.Roster
	stCl         *libstate.Client
	execCl       *libexec.Client
	thCl         *threshold.Client

	threshMap   map[string]int
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
	_, err := s.execCl.InitUnit(s.threshMap[execbase.UID])
	if err != nil {
		log.Errorf("initializing execution unit: %v", err)
		return err
	}
	s.thCl = threshold.NewClient(s.threshRoster)
	_, err = s.thCl.InitUnit(s.threshMap[thbase.UID])
	if err != nil {
		log.Errorf("initializing threshold unit: %v", err)
		return err
	}
	return nil
}

func (s *SimulationService) initContract() error {
	if s.Batched {
		s.ContractFile = s.BatchContractFile
	}
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
	reply, err := s.stCl.InitContract(raw, hdr, args, 1)
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
	inReceipts := make(map[int]map[string]*core.OpcodeReceipt)

	// Get state
	gcs, err := s.stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return err
	}

	// Initialize transaction
	m1 := monitor.NewTimeMeasure("setup_inittxn")
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
	m1.Record()

	// Step 1: init_dkg
	m2 := monitor.NewTimeMeasure("setup_initdkg")
	dkgReply, err := s.thCl.InitDKG(execReq)
	if err != nil {
		log.Error(err)
		return err
	}
	m2.Record()

	// Step 2: exec
	m3 := monitor.NewTimeMeasure("setup_exec")
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
	m3.Record()

	// Step 3: update_state
	m4 := monitor.NewTimeMeasure("setup_update")
	var setupOut dkglottery.SetupOutput
	err = protobuf.Decode(execReply.Output.Data, &setupOut)
	if err != nil {
		log.Error(err)
		return err
	}
	inReceipts[execReq.Index] = execReply.InputReceipts
	execReq.Index = 2
	execReq.OpReceipts = execReply.OutputReceipts

	_, err = s.stCl.UpdateState(setupOut.WS, execReq, inReceipts, commons.UPDATE_WAIT)
	if err != nil {
		log.Error(err)
		return err
	}
	_, err = s.stCl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, commons.PROOF_WAIT)
	if err != nil {
		log.Error(err)
	}
	s.X = dkgReply.Output.X
	m4.Record()
	return err
}

func (s *SimulationService) executeBatchJoin(idx int) error {
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
	lastRoot := gcs.Proof.Proof.InclusionProof.GetRoot()

	joinMonitor := monitor.NewTimeMeasure(fmt.Sprintf("batch_join_%d", idx))

	var encTickets utils.ElGamalPairs
	for i := 0; i < s.BatchSize; i++ {
		encTickets.Pairs = append(encTickets.Pairs, commons.GenerateTicket(s.X))
	}

	input := dkglottery.BatchJoinInput{
		Tickets: dkglottery.BatchTicket{Data: encTickets},
	}
	data, err := protobuf.Encode(&input)
	if err != nil {
		log.Errorf("encoding input: %v", err)
		return err
	}
	itReply, err := execCl.InitTransaction(s.rdata, cdata, "joinwf", "join")
	if err != nil {
		log.Errorf("initializing txn: %v", err)
		return err
	}

	// Step 1: execute
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "batch_join_dkglot",
		Data:        data,
		StateProofs: sp,
	}
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	execReply, err := execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing batch_join_dkglot: %v", err)
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
	_, err = stCl.UpdateState(joinOut.WS, execReq, nil, commons.UPDATE_WAIT)
	if err != nil {
		log.Error(err)
		return err
	}
	_, err = stCl.WaitProof(s.CID[:], lastRoot, commons.PROOF_WAIT)
	if err != nil {
		log.Error(err)
		return err
	}
	joinMonitor.Record()
	return nil
}

func (s *SimulationService) executeJoin(idx int) error {
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
	lastRoot := gcs.Proof.Proof.InclusionProof.GetRoot()

	label := fmt.Sprintf("p%d_join", idx)
	joinMonitor := monitor.NewTimeMeasure(label)

	// Prepare ticket
	ticket := commons.GenerateTicket(s.X)
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
		_, err = stCl.UpdateState(joinOut.WS, execReq, nil, commons.UPDATE_WAIT)
		if err != nil {
			pr, err := stCl.WaitProof(execReq.EP.CID, lastRoot, commons.PROOF_WAIT)
			if err != nil {
				log.Errorf("wait proof: %v", err)
				return err
			}
			gcs.Proof.Proof = pr
			cdata.Proof = gcs.Proof.Proof
			lastRoot = pr.InclusionProof.GetRoot()
			//log.Info("retry:", idx)
		} else {
			_, err := stCl.WaitProof(s.CID[:], lastRoot, commons.PROOF_WAIT)
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

	// Initialize transaction
	m1 := monitor.NewTimeMeasure("close_inittxn")
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}
	itReply, err := s.execCl.InitTransaction(s.rdata, cdata, "closewf", "close")
	if err != nil {
		log.Errorf("initializing txn: %v", err)
		return err
	}
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	m1.Record()

	// Step 1: exec
	m2 := monitor.NewTimeMeasure("close_exec")
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
	execReply, err := s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing close_dkglot: %v", err)
		return err
	}
	m2.Record()

	// Step 2: update_state
	m3 := monitor.NewTimeMeasure("close_update")
	var closeOut dkglottery.CloseOutput
	err = protobuf.Decode(execReply.Output.Data, &closeOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts

	_, err = s.stCl.UpdateState(closeOut.WS, execReq, nil, commons.UPDATE_WAIT)
	if err != nil {
		log.Errorf("updating state: %v", err)
		return err
	}
	// Wait for proof
	_, err = s.stCl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, commons.PROOF_WAIT)
	if err != nil {
		log.Errorf("wait proof: %v", err)
	}
	m3.Record()
	return err
}

func (s *SimulationService) executeFinalize() error {
	inReceipts := make(map[int]map[string]*core.OpcodeReceipt)

	// Get state
	gcs, err := s.stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return err
	}

	// Initialize transaction
	m1 := monitor.NewTimeMeasure("finalize_inittxn")
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}
	itReply, err := s.execCl.InitTransaction(s.rdata, cdata, "finalizewf",
		"finalize")
	if err != nil {
		log.Errorf("initializing txn: %v", err)
		return err
	}
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	m1.Record()

	// Step 1: exec
	m2 := monitor.NewTimeMeasure("finalize_exec_1")
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "prepare_decrypt_dkglot",
		StateProofs: sp,
	}
	execReply, err := s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing prepare_decrypt_dkglot: %v", err)
		return err
	}
	m2.Record()

	// Step 2: decrypt
	m3 := monitor.NewTimeMeasure("finalize_decrypt")
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
	m3.Record()

	// Step 3: exec
	m4 := monitor.NewTimeMeasure("finalize_exec_2")
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
	inReceipts[execReq.Index] = decReply.InputReceipts
	execReq.Index = 2
	execReq.OpReceipts = decReply.OutputReceipts
	execReply, err = s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing finalize_dkglot: %v", err)
		return err
	}
	m4.Record()

	// Step 4: update_state
	m5 := monitor.NewTimeMeasure("finalize_update")
	var finalOut dkglottery.FinalizeOutput
	err = protobuf.Decode(execReply.Output.Data, &finalOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	inReceipts[execReq.Index] = execReply.InputReceipts
	execReq.Index = 3
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = s.stCl.UpdateState(finalOut.WS, execReq, inReceipts, commons.UPDATE_WAIT)
	if err != nil {
		log.Errorf("updating state: %v", err)
		return err
	}

	// Wait for proof
	_, err = s.stCl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, commons.PROOF_WAIT)
	if err != nil {
		log.Errorf("wait proof: %v", err)
	}
	m5.Record()
	return err
}

func (s *SimulationService) runDKGLottery() error {
	schedule, err := commons.ReadSchedule(s.ScheduleFile, s.NumParticipants)
	if err != nil {
		return err
	}
	// Initialize DFUs
	err = s.initDFUs()
	if err != nil {
		log.Error(err)
		return err
	}
	_, err = s.thCl.InitDKG(&core.ExecutionRequest{EP: nil})
	if err != nil {
		log.Error(err)
		return err
	}
	for round := 0; round < s.Rounds; round++ {
		// Setting up the state unit in this loop otherwise we would build
		// on a single blockchain, which means later rounds would have larger
		// Byzcoin proofs
		s.byzID, err = commons.SetupStateUnit(s.stRoster, s.BlockTime)
		if err != nil {
			log.Error(err)
		}
		s.stCl = libstate.NewClient(byzcoin.NewClient(s.byzID, *s.stRoster))

		var wg sync.WaitGroup
		var ongoing int64
		ctr := 0
		// Initialize contract
		err = s.initContract()
		if err != nil {
			return err
		}
		// setup_txn
		err = s.executeSetup()
		if err != nil {
			return err
		}
		// join_txn
		i := 0
		for i < len(schedule) {
			pCount := schedule[i]
			if pCount == 0 {
				i++
			} else {
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
				wg.Wait()
				i++
			}
		}
		// close_txn
		err = s.executeClose()
		if err != nil {
			return err
		}
		// finalize_txn
		err = s.executeFinalize()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SimulationService) runBatchedLottery() error {
	// Initialize DFUs
	err := s.initDFUs()
	if err != nil {
		log.Error(err)
		return err
	}
	_, err = s.thCl.InitDKG(&core.ExecutionRequest{EP: nil})
	if err != nil {
		log.Error(err)
		return err
	}
	for round := 0; round < s.Rounds; round++ {
		// Setting up the state unit in this loop otherwise we would build
		// on a single blockchain, which means later rounds would have larger
		// Byzcoin proofs
		s.byzID, err = commons.SetupStateUnit(s.stRoster, s.BlockTime)
		if err != nil {
			log.Error(err)
		}
		s.stCl = libstate.NewClient(byzcoin.NewClient(s.byzID, *s.stRoster))

		// Initialize contract
		err = s.initContract()
		if err != nil {
			return err
		}
		// setup_txn
		err = s.executeSetup()
		if err != nil {
			return err
		}
		// join_txn
		for i := 0; i < commons.BATCH_COUNT; i++ {
			err = s.executeBatchJoin(i)
			if err != nil {
				return err
			}
		}
		// close_txn
		err = s.executeClose()
		if err != nil {
			return err
		}
		// finalize_txn
		err = s.executeFinalize()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SimulationService) dummyRecords() {
	for i := s.NumParticipants; i < 1000; i++ {
		label := fmt.Sprintf("p%d_join", i)
		for round := 0; round < s.Rounds; round++ {
			dummy := monitor.NewTimeMeasure(label)
			time.Sleep(1 * time.Millisecond)
			dummy.Record()
		}
	}
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	regRoster := onet.NewRoster(config.Roster.List[0:4])
	s.stRoster = onet.NewRoster(config.Roster.List[4:23])
	s.execRoster = onet.NewRoster(config.Roster.List[23:36])
	s.threshRoster = onet.NewRoster(config.Roster.List[36:])

	s.stRoster.List[0] = config.Roster.List[0]
	s.execRoster.List[0] = config.Roster.List[0]
	s.threshRoster.List[0] = config.Roster.List[0]

	keyMap := make(map[string][]kyber.Point)
	keyMap[statebase.UID] = s.stRoster.ServicePublics(skipchain.ServiceName)
	keyMap[execbase.UID] = s.execRoster.ServicePublics(libexec.ServiceName)
	keyMap[thbase.UID] = s.threshRoster.ServicePublics(blscosi.ServiceName)
	s.rdata, s.threshMap, err = commons.SetupRegistry(regRoster, &s.DFUFile,
		keyMap, s.BlockTime)
	if err != nil {
		log.Error(err)
	}
	if s.Batched {
		s.BatchSize = s.NumParticipants / 10
		err = s.runBatchedLottery()
	} else {
		err = s.runDKGLottery()
		s.dummyRecords()
	}
	return err
}
