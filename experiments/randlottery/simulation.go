package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	statebase "github.com/dedis/protean/libstate/base"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3"

	"github.com/BurntSushi/toml"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyrand"
	randbase "github.com/dedis/protean/easyrand/base"
	"github.com/dedis/protean/experiments/commons"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	"github.com/dedis/protean/libexec/apps/randlottery"
	execbase "github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/libstate"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
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
	SlotFactor      int
	Seed            int

	// internal structs
	byzID      skipchain.SkipBlockID
	stRoster   *onet.Roster
	execRoster *onet.Roster
	randRoster *onet.Roster
	stCl       *libstate.Client
	execCl     *libexec.Client
	randCl     *easyrand.Client

	threshMap   map[string]int
	rdata       *execbase.ByzData
	CID         byzcoin.InstanceID
	contractGen *skipchain.SkipBlock
}

func init() {
	onet.SimulationRegister("RandLottery", NewRandLottery)
}

func NewRandLottery(config string) (onet.Simulation, error) {
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
	s.randCl = easyrand.NewClient(s.randRoster)
	_, err = s.randCl.InitUnit(s.threshMap[randbase.UID])
	if err != nil {
		log.Errorf("initializing randomness unit: %v", err)
		return err
	}
	_, err = s.randCl.InitDKG()
	if err != nil {
		log.Errorf("initializing DKG: %v", err)
		return err
	}
	s.randCl.CreateRandomness()
	s.randCl.CreateRandomness()
	s.randCl.CreateRandomness()
	s.randCl.CreateRandomness()
	// Setup the state unit
	s.byzID, err = commons.SetupStateUnit(s.stRoster, s.BlockTime)
	if err != nil {
		log.Error(err)
	}
	return err
}

func (s *SimulationService) generateSchedule() []int {
	if s.NumParticipants < 1000 {
		numSlots := s.NumParticipants * s.SlotFactor
		return commons.GenerateSchedule(s.Seed, s.NumParticipants, numSlots)
	} else {
		// if s.NumParticipants == 1000, use the schedule from 500
		halfSlots := (s.NumParticipants / 2) * s.SlotFactor
		half := commons.GenerateSchedule(s.Seed, s.NumParticipants/2, halfSlots)
		slots := make([]int, halfSlots*2)
		copy(slots, half)
		copy(slots[halfSlots:], half)
		return slots
	}
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
	tickets := randlottery.Tickets{}
	buf, err := protobuf.Encode(&tickets)
	if err != nil {
		log.Error(err)
		return err
	}
	args := byzcoin.Arguments{{Name: "tickets", Value: buf}}
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

func (s *SimulationService) executeJoin(signer darc.Signer, idx int) error {
	execCl := libexec.NewClient(s.execRoster)
	stCl := libstate.NewClient(byzcoin.NewClient(s.byzID, *s.stRoster))
	defer execCl.Close()
	defer stCl.Close()

	label := fmt.Sprintf("p%d_join", idx)
	joinMonitor := monitor.NewTimeMeasure(label)

	// Prepare ticket
	pkHash, err := utils.HashPoint(signer.Ed25519.Point)
	if err != nil {
		log.Errorf("hashing point: %v", err)
		return err
	}
	sig, err := signer.Ed25519.Sign(pkHash)
	input := randlottery.JoinInput{
		Ticket: randlottery.Ticket{
			Key: signer.Ed25519.Point,
			Sig: sig,
		},
	}
	data, err := protobuf.Encode(&input)
	if err != nil {
		log.Errorf("encoding input: %v", err)
		return err
	}
	// Get state
	gcs, err := stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return err
	}
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}
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
			FnName:      "join_randlot",
			Data:        data,
			StateProofs: sp,
		}
		execReq := &core.ExecutionRequest{
			Index: 0,
			EP:    &itReply.Plan,
		}
		execReply, err := s.execCl.Execute(execInput, execReq)
		if err != nil {
			log.Errorf("executing join_randlot: %v", err)
			return err
		}
		// Step 2: update_state
		var joinOut randlottery.JoinOutput
		err = protobuf.Decode(execReply.Output.Data, &joinOut)
		if err != nil {
			log.Errorf("decoding join output: %v", err)
			return err
		}
		execReq.Index = 1
		execReq.OpReceipts = execReply.OutputReceipts
		_, err = stCl.UpdateState(joinOut.WS, execReq, nil, commons.UPDATE_WAIT)
		if err != nil {
			log.Errorf("update state: %v", err)
			pr, err := stCl.WaitProof(s.CID[:], lastRoot, s.BlockTime)
			if err != nil {
				log.Errorf("wait proof: %v", err)
				return err
			}
			gcs.Proof.Proof = pr
			cdata.Proof = gcs.Proof.Proof
			lastRoot = pr.InclusionProof.GetRoot()
		} else {
			_, err = stCl.WaitProof(s.CID[:], lastRoot, s.BlockTime)
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
	closeMonitor := monitor.NewTimeMeasure("close")
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
	closeInput := randlottery.CloseInput{
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
		FnName:      "close_randlot",
		Data:        data,
		StateProofs: sp,
	}
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	execReply, err := s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing close_randlot: %v", err)
		return err
	}

	// Step 2: update_state
	var closeOut randlottery.CloseOutput
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
	_, err = s.stCl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, s.BlockTime)
	if err != nil {
		log.Errorf("wait proof: %v", err)
	}
	closeMonitor.Record()
	return err
}

func (s *SimulationService) executeFinalize() error {
	inReceipts := make(map[int]map[string]*core.OpcodeReceipt)
	finalizeMonitor := monitor.NewTimeMeasure("finalize")
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
	round := uint64(2)
	// Step 1: randomness
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	randReply, err := s.randCl.GetRandomness(round, execReq)
	if err != nil {
		log.Errorf("getting randomness: %v", err)
		return err
	}

	// Step 2: exec
	finalizeInput := randlottery.FinalizeInput{
		Round:      round,
		Randomness: randReply.Output,
	}
	data, err := protobuf.Encode(&finalizeInput)
	if err != nil {
		log.Errorf("protobuf encode: %v", err)
		return err
	}
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "finalize_randlot",
		Data:        data,
		StateProofs: sp,
	}
	execReq.Index = 1
	execReq.OpReceipts = randReply.Receipts
	execReply, err := s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing finalize_randlot: %v", err)
		return err
	}

	// Step 3: update_state
	var finalOut randlottery.FinalizeOutput
	err = protobuf.Decode(execReply.Output.Data, &finalOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	inReceipts[execReq.Index] = execReply.InputReceipts
	execReq.Index = 2
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = s.stCl.UpdateState(finalOut.WS, execReq, inReceipts, commons.UPDATE_WAIT)
	if err != nil {
		log.Errorf("updating state: %v", err)
		return err
	}

	// Wait for proof
	_, err = s.stCl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, s.BlockTime)
	if err != nil {
		log.Errorf("wait proof: %v", err)
	}
	finalizeMonitor.Record()
	return err
}

func (s *SimulationService) runRandLottery() error {
	participants := commons.GenerateWriters(s.NumParticipants)
	//schedule := commons.GenerateSchedule(s.Seed, s.NumParticipants, s.NumSlots)
	schedule := s.generateSchedule()
	// Initialize DFUs
	err := s.initDFUs()
	if err != nil {
		return err
	}
	s.stCl = libstate.NewClient(byzcoin.NewClient(s.byzID, *s.stRoster))

	for round := 0; round < s.Rounds; round++ {
		var wg sync.WaitGroup
		var ongoing int64
		ctr := 0
		// Initialize contract
		err = s.initContract()
		if err != nil {
			return err
		}
		// join_txn
		for i := 0; i < len(schedule); i++ {
			pCount := schedule[i]
			if pCount != 0 {
				wg.Add(pCount)
				for j := 0; j < pCount; j++ {
					go func(idx int) {
						defer wg.Done()
						atomic.AddInt64(&ongoing, 1)
						err = s.executeJoin(participants[idx], idx)
						atomic.AddInt64(&ongoing, -1)
					}(ctr)
					ctr++
				}
			} else {
				count := atomic.LoadInt64(&ongoing)
				if count == 0 {
					continue
				}
			}
			time.Sleep(time.Duration(s.BlockTime) * time.Second)
		}
		wg.Wait()
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

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	regRoster := onet.NewRoster(config.Roster.List[0:4])
	//s.execRoster = onet.NewRoster(config.Roster.List[0:13])
	//s.randRoster = onet.NewRoster(config.Roster.List[0:13])
	//s.stRoster = config.Roster

	s.stRoster = onet.NewRoster(config.Roster.List[4:23])
	s.execRoster = onet.NewRoster(config.Roster.List[23:36])
	s.randRoster = onet.NewRoster(config.Roster.List[36:])
	s.stRoster.List[0] = config.Roster.List[0]
	s.execRoster.List[0] = config.Roster.List[0]
	s.randRoster.List[0] = config.Roster.List[0]

	keyMap := make(map[string][]kyber.Point)
	keyMap[statebase.UID] = s.stRoster.ServicePublics(skipchain.ServiceName)
	keyMap[execbase.UID] = s.execRoster.ServicePublics(libexec.ServiceName)
	keyMap[randbase.UID] = s.randRoster.ServicePublics(blscosi.ServiceName)
	s.rdata, s.threshMap, err = commons.SetupRegistry(regRoster, &s.DFUFile,
		keyMap, s.BlockTime)
	if err != nil {
		log.Error(err)
	}
	err = s.runRandLottery()
	return err
}
