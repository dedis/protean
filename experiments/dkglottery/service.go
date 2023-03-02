package main

import (
	"github.com/BurntSushi/toml"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/experiments/commons"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	"github.com/dedis/protean/libexec/apps/dkglottery"
	"github.com/dedis/protean/libexec/apps/randlottery"
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
	"go.dedis.ch/protobuf"
	"sync"
	"time"
)

type SimulationService struct {
	onet.SimulationBFTree
	ContractFile    string
	FSMFile         string
	DFUFile         string
	NumParticipants int
	BlockTime       int
	BlockWait       int

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
	execReq.Index = 2
	execReq.OpReceipts = execReply.Receipts
	_, err = s.stCl.UpdateState(setupOut.WS, execReq, 5)
	if err != nil {
		log.Error(err)
		return err
	}
	_, err = s.stCl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, 5)
	if err != nil {
		log.Error(err)
	}
	s.X = dkgReply.Output.X
	return err
}

func (s *SimulationService) executeJoin(ticket utils.ElGamalPair) (time.Duration, error) {
	execCl := libexec.NewClient(s.execRoster)
	stCl := libstate.NewClient(byzcoin.NewClient(s.byzID, *s.stRoster))
	defer execCl.Close()
	defer stCl.Close()

	start := time.Now()

	gcs, err := stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return 0, err
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
		return 0, err
	}
	lastRoot := gcs.Proof.Proof.InclusionProof.GetRoot()
	done := false
	for !done {
		itReply, err := execCl.InitTransaction(s.rdata, cdata, "joinwf", "join")
		if err != nil {
			log.Errorf("initializing txn: %v", err)
			return 0, err
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
			return 0, err
		}
		// Step 2: update_state
		var joinOut randlottery.JoinOutput
		err = protobuf.Decode(execReply.Output.Data, &joinOut)
		if err != nil {
			log.Errorf("decoding join output: %v", err)
			return 0, err
		}
		execReq.Index = 1
		execReq.OpReceipts = execReply.Receipts
		_, err = stCl.UpdateState(joinOut.WS, execReq, 5)
		if err != nil {
			pr, err := stCl.WaitProof(s.CID[:], lastRoot, 10)
			if err != nil {
				log.Errorf("wait proof: %v", err)
				return 0, err
			}
			gcs.Proof.Proof = pr
			cdata.Proof = gcs.Proof.Proof
			lastRoot = pr.InclusionProof.GetRoot()
		} else {
			_, err := stCl.WaitProof(s.CID[:], lastRoot, 10)
			if err != nil {
				log.Errorf("wait proof: %v", err)
				return 0, err
			}
			done = true
		}
	}
	timeWait := time.Since(start)
	return timeWait, nil
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
	times := make([]time.Duration, s.NumParticipants)
	tickets := commons.GenerateTickets(s.X, s.NumParticipants)
	var wg sync.WaitGroup
	schedule := []int{0, 1, 0, 2, 1, 0, 1, 0, 2, 1, 0, 0, 1, 1, 0}
	//schedule := []int{0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1}
	ctr := 0
	for i := 0; i < len(schedule); i++ {
		pCount := schedule[i]
		if pCount != 0 {
			wg.Add(pCount)
			for j := 0; j < pCount; j++ {
				go func(idx int) {
					defer wg.Done()
					times[idx], err = s.executeJoin(tickets[idx])
				}(ctr)
				ctr++
			}
		}
		time.Sleep(time.Duration(s.BlockTime) * time.Second)
		//if pCount == 0 {
		//	time.Sleep(time.Duration(s.BlockTime) * time.Second)
		//} else {
		//	wg.Add(pCount)
		//	for j := 0; j < pCount; j++ {
		//		go func(idx int) {
		//			defer wg.Done()
		//			times[idx], err = s.executeJoin(tickets[idx])
		//		}(ctr)
		//		ctr++
		//	}
		//}
	}
	wg.Wait()
	log.Info(times)
	return nil
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	//regRoster := onet.NewRoster(config.Roster.List[0:4])
	//s.stRoster = onet.NewRoster(config.Roster.List[4:])
	//s.execRoster = onet.NewRoster(config.Roster.List[4:])
	//s.threshRoster = onet.NewRoster(config.Roster.List[4:])
	regRoster := config.Roster
	s.stRoster = config.Roster
	s.execRoster = config.Roster
	s.threshRoster = config.Roster

	keyMap := make(map[string][]kyber.Point)
	keyMap["state"] = s.stRoster.ServicePublics(skipchain.ServiceName)
	keyMap["codeexec"] = s.execRoster.ServicePublics(libexec.ServiceName)
	keyMap["threshold"] = s.threshRoster.ServicePublics(blscosi.ServiceName)
	s.rdata, err = commons.SetupRegistry(regRoster, &s.DFUFile, keyMap)
	if err != nil {
		log.Error(err)
	}
	err = s.runDKGLottery()
	if err != nil {
		return err
	}
	return nil
}
