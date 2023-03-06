package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyneff"
	"github.com/dedis/protean/experiments/commons"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	evotingpc "github.com/dedis/protean/libexec/apps/evoting_pc"
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
	shufRoster   *onet.Roster
	threshRoster *onet.Roster
	stCl         *libstate.Client
	execCl       *libexec.Client
	shCl         *easyneff.Client
	thCl         *threshold.Client

	rdata       *execbase.ByzData
	CID         byzcoin.InstanceID
	contractGen *skipchain.SkipBlock
	X           kyber.Point
}

func init() {
	onet.SimulationRegister("Evoting", NewEvotingService)
}

func NewEvotingService(config string) (onet.Simulation, error) {
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
	s.shCl = easyneff.NewClient(s.shufRoster)
	_, err = s.shCl.InitUnit()
	if err != nil {
		log.Errorf("initializing shuffle unit: %v", err)
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
	encBallots := evotingpc.EncBallots{}
	buf, err := protobuf.Encode(&encBallots)
	if err != nil {
		log.Error(err)
		return err
	}
	args := byzcoin.Arguments{{Name: "enc_ballots", Value: buf}}
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
	setupInput := evotingpc.SetupInput{Pk: dkgReply.Output.X}
	data, err := protobuf.Encode(&setupInput)
	if err != nil {
		log.Error(err)
		return err
	}
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "setup_vote_pc",
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
	var setupOut evotingpc.SetupOutput
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
	_, err = s.stCl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, s.BlockTime)
	if err != nil {
		log.Error(err)
	}
	s.X = dkgReply.Output.X
	return err
}

func (s *SimulationService) executeVote(ballot string, idx int) error {
	execCl := libexec.NewClient(s.execRoster)
	stCl := libstate.NewClient(byzcoin.NewClient(s.byzID, *s.stRoster))
	defer execCl.Close()
	defer stCl.Close()

	label := fmt.Sprintf("p%d_vote", idx)

	voteMonitor := monitor.NewTimeMeasure(label)
	gcs, err := stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return err
	}
	lastRoot := gcs.Proof.Proof.InclusionProof.GetRoot()
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}
	// Prepare input
	encBallot := utils.ElGamalEncrypt(s.X, []byte(ballot))
	input := evotingpc.VoteInput{
		Ballot: evotingpc.Ballot{Data: encBallot},
	}
	data, err := protobuf.Encode(&input)
	if err != nil {
		log.Errorf("encoding input: %v", err)
		return err
	}
	done := false
	for !done {
		itReply, err := execCl.InitTransaction(s.rdata, cdata, "votewf", "vote")
		if err != nil {
			log.Errorf("initializing txn: %v", err)
			return err
		}
		// Step 1: execute
		sp := make(map[string]*core.StateProof)
		sp["readset"] = &gcs.Proof
		execInput := execbase.ExecuteInput{
			FnName:      "vote_pc",
			Data:        data,
			StateProofs: sp,
		}
		execReq := &core.ExecutionRequest{
			Index: 0,
			EP:    &itReply.Plan,
		}
		execReply, err := execCl.Execute(execInput, execReq)
		if err != nil {
			log.Errorf("executing vote_pc: %v", err)
			return err
		}
		// Step 2: update_state
		var voteOut evotingpc.VoteOutput
		err = protobuf.Decode(execReply.Output.Data, &voteOut)
		if err != nil {
			log.Errorf("decoding vote output: %v", err)
			return err
		}
		execReq.Index = 1
		execReq.OpReceipts = execReply.Receipts
		_, err = stCl.UpdateState(voteOut.WS, execReq, 5)
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
	voteMonitor.Record()
	return nil
}

func (s *SimulationService) executeLock() error {
	// Get state
	gcs, err := s.stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return err
	}
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}

	// Initialize transaction
	itReply, err := s.execCl.InitTransaction(s.rdata, cdata, "finalizewf", "lock")
	if err != nil {
		log.Errorf("initializing txn: %v", err)
		return err
	}
	// Step 1: exec
	lockInput := evotingpc.LockInput{
		Barrier: 0,
	}
	data, err := protobuf.Encode(&lockInput)
	if err != nil {
		log.Errorf("encoding close input: %v", err)
		return err
	}
	hBuf, err := s.X.MarshalBinary()
	if err != nil {
		log.Errorf("marshaling point: %v", err)
		return err
	}
	pc := &core.KVDict{Data: make(map[string][]byte)}
	pc.Data["h"] = hBuf
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "lock",
		Data:        data,
		StateProofs: sp,
		Precommits:  pc,
	}
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	execReply, err := s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing lock: %v", err)
		return err
	}

	// Step 2: update_state
	var lockOut evotingpc.LockOutput
	err = protobuf.Decode(execReply.Output.Data, &lockOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	execReq.Index = 1
	execReq.OpReceipts = execReply.Receipts
	_, err = s.stCl.UpdateState(lockOut.WS, execReq, 5)
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

func (s *SimulationService) executeShuffle() error {
	// Get state
	gcs, err := s.stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return err
	}
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}

	// Initialize transaction
	itReply, err := s.execCl.InitTransaction(s.rdata, cdata, "finalizewf", "shuffle")
	if err != nil {
		log.Errorf("initializing txn: %v", err)
		return err
	}

	// Step 1: exec
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "prepare_shuffle_pc",
		StateProofs: sp,
	}
	execReply, err := s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing prepare_shuffle_pc: %v", err)
		return err
	}

	// Step 2: shuffle
	var prepShOut evotingpc.PrepShufOutput
	err = protobuf.Decode(execReply.Output.Data, &prepShOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	execReq.Index = 1
	execReq.OpReceipts = execReply.Receipts
	shReply, err := s.shCl.Shuffle(prepShOut.Input.Pairs, prepShOut.Input.H, execReq)
	if err != nil {
		log.Errorf("shuffle: %v", err)
		return err
	}

	// Step 3: exec
	prepPrInput := evotingpc.PrepProofsInput{ShProofs: shReply.Proofs}
	data, err := protobuf.Encode(&prepPrInput)
	if err != nil {
		log.Errorf("protobuf encode: %v", err)
		return err
	}
	execInput = execbase.ExecuteInput{
		FnName:      "prepare_proofs_pc",
		Data:        data,
		StateProofs: sp,
	}
	execReq.Index = 2
	execReq.OpReceipts = shReply.Receipts
	execReply, err = s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing prepare_proofs_pc: %v", err)
		return err
	}

	// Step 4: update_state
	var prepPrOut evotingpc.PrepProofsOutput
	err = protobuf.Decode(execReply.Output.Data, &prepPrOut)
	if err != nil {
		log.Errorf("protpbuf decode: %v", err)
		return err
	}
	execReq.Index = 3
	execReq.OpReceipts = execReply.Receipts
	_, err = s.stCl.UpdateState(prepPrOut.WS, execReq, 5)

	_, err = s.stCl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, 5)
	if err != nil {
		log.Errorf("wait proof: %v", err)
	}
	return err
}

func (s *SimulationService) executeTally() error {
	// Get state
	gcs, err := s.stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return err
	}
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}

	// Initialize transaction
	itReply, err := s.execCl.InitTransaction(s.rdata, cdata, "finalizewf", "tally")
	if err != nil {
		log.Errorf("initializing txn: %v", err)
		return err
	}

	// Step 1: exec
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "prepare_decrypt_vote_pc",
		StateProofs: sp,
	}
	execReply, err := s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing prepare_decrypt_vote_pc: %v", err)
		return err
	}

	// Step 2: decrypt
	var prepDecOut evotingpc.PrepDecOutput
	err = protobuf.Decode(execReply.Output.Data, &prepDecOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	execReq.Index = 1
	execReq.OpReceipts = execReply.Receipts
	decReply, err := s.thCl.Decrypt(&prepDecOut.Input, execReq)
	if err != nil {
		log.Errorf("decrypting: %v", err)
		return err
	}

	// Step 3: exec
	tallyIn := evotingpc.TallyInput{
		CandCount: 5,
		Ps:        decReply.Output.Ps,
	}
	data, err := protobuf.Encode(&tallyIn)
	if err != nil {
		log.Errorf("protobuf encode: %v", err)
		return err
	}
	execInput = execbase.ExecuteInput{
		FnName:      "tally_pc",
		Data:        data,
		StateProofs: sp,
	}
	execReq.Index = 2
	execReq.OpReceipts = decReply.Receipts
	execReply, err = s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing tally_pc: %v", err)
		return err
	}

	// Step 4: update_state
	var tallyOut evotingpc.TallyOutput
	err = protobuf.Decode(execReply.Output.Data, &tallyOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	execReq.Index = 3
	execReq.OpReceipts = execReply.Receipts
	_, err = s.stCl.UpdateState(tallyOut.WS, execReq, 5)
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

func (s *SimulationService) runEvoting() error {
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
	ballots := commons.GenerateBallots(s.NumParticipants)
	schedule := commons.GenerateSchedule(s.Seed, s.NumParticipants, s.NumSlots)
	log.Info(schedule)
	ctr := 0
	for i := 0; i < len(schedule); i++ {
		pCount := schedule[i]
		if pCount != 0 {
			wg.Add(pCount)
			for j := 0; j < pCount; j++ {
				go func(idx int) {
					defer wg.Done()
					err = s.executeVote(ballots[idx], idx)
				}(ctr)
				ctr++
			}
		}
		time.Sleep(time.Duration(s.BlockTime) * time.Second)
	}
	wg.Wait()
	err = s.executeLock()
	if err != nil {
		return err
	}
	err = s.executeShuffle()
	if err != nil {
		return err
	}
	err = s.executeTally()
	return err
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	regRoster := onet.NewRoster(config.Roster.List[0:4])
	//s.stRoster = onet.NewRoster(config.Roster.List[10:])
	//s.execRoster = s.stRoster
	//s.shufRoster = onet.NewRoster(config.Roster.List[4:])
	//s.threshRoster = s.stRoster
	s.stRoster = onet.NewRoster(config.Roster.List[4:])
	s.execRoster = s.stRoster
	s.shufRoster = s.stRoster
	s.threshRoster = s.stRoster

	keyMap := make(map[string][]kyber.Point)
	keyMap["state"] = s.stRoster.ServicePublics(skipchain.ServiceName)
	keyMap["codeexec"] = s.execRoster.ServicePublics(libexec.ServiceName)
	keyMap["easyneff"] = s.shufRoster.ServicePublics(blscosi.ServiceName)
	keyMap["threshold"] = s.threshRoster.ServicePublics(blscosi.ServiceName)
	s.rdata, err = commons.SetupRegistry(regRoster, &s.DFUFile, keyMap)
	if err != nil {
		log.Error(err)
	}
	err = s.runEvoting()
	return err
}
