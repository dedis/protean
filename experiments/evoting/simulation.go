package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	statebase "github.com/dedis/protean/libstate/base"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3/util/key"

	"github.com/BurntSushi/toml"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyneff"
	neffbase "github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/experiments/commons"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	evotingpc "github.com/dedis/protean/libexec/apps/evoting_pc"
	execbase "github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/libstate"
	"github.com/dedis/protean/threshold"
	thbase "github.com/dedis/protean/threshold/base"
	"github.com/dedis/protean/utils"
	protean "github.com/dedis/protean/utils"
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
	NumCandidates     int
	NumParticipants   int
	Batched           bool
	BatchSize         int

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

	threshMap   map[string]int
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
	_, err := s.execCl.InitUnit(s.threshMap[execbase.UID])
	if err != nil {
		log.Errorf("initializing execution unit: %v", err)
		return err
	}
	s.shCl = easyneff.NewClient(s.shufRoster)
	_, err = s.shCl.InitUnit(s.threshMap[neffbase.UID])
	if err != nil {
		log.Errorf("initializing shuffle unit: %v", err)
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
	m3.Record()

	// Step 3: update_state
	m4 := monitor.NewTimeMeasure("setup_update")
	var setupOut evotingpc.SetupOutput
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

func (s *SimulationService) executeBatchVote(ballots []string, idx int) error {
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

	voteMonitor := monitor.NewTimeMeasure(fmt.Sprintf("batch_vote_%d", idx))

	var encBallots utils.ElGamalPairs
	for _, b := range ballots {
		encBallot := utils.ElGamalEncrypt(s.X, []byte(b))
		encBallots.Pairs = append(encBallots.Pairs, encBallot)
	}

	input := evotingpc.BatchVoteInput{
		Ballots: evotingpc.BatchBallot{Data: encBallots},
	}
	data, err := protobuf.Encode(&input)
	if err != nil {
		log.Errorf("encoding input: %v", err)
		return err
	}

	itReply, err := execCl.InitTransaction(s.rdata, cdata, "votewf", "vote")
	if err != nil {
		log.Errorf("initializing txn: %v", err)
		return err
	}
	// Step 1: execute
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "batch_vote_pc",
		Data:        data,
		StateProofs: sp,
	}
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	execReply, err := execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing batch_vote_pc: %v", err)
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
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = stCl.UpdateState(voteOut.WS, execReq, nil, commons.UPDATE_WAIT)
	if err != nil {
		log.Error(err)
		return err
	}
	_, err = stCl.WaitProof(s.CID[:], lastRoot, commons.PROOF_WAIT)
	if err != nil {
		log.Error(err)
		return err
	}
	voteMonitor.Record()
	return nil
}

func (s *SimulationService) executeVote(ballot string, idx int) error {
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

	label := fmt.Sprintf("p%d_vote", idx)
	voteMonitor := monitor.NewTimeMeasure(label)

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
		execReq.OpReceipts = execReply.OutputReceipts
		_, err = stCl.UpdateState(voteOut.WS, execReq, nil, commons.UPDATE_WAIT)
		if err != nil {
			pr, err := stCl.WaitProof(s.CID[:], lastRoot, commons.PROOF_WAIT)
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

	// Initialize transaction
	m1 := monitor.NewTimeMeasure("lock_inittxn")
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}
	itReply, err := s.execCl.InitTransaction(s.rdata, cdata, "finalizewf", "lock")
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
	m2 := monitor.NewTimeMeasure("lock_exec")
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
	execReply, err := s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing lock: %v", err)
		return err
	}
	m2.Record()

	// Step 2: update_state
	m3 := monitor.NewTimeMeasure("lock_update")
	var lockOut evotingpc.LockOutput
	err = protobuf.Decode(execReply.Output.Data, &lockOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = s.stCl.UpdateState(lockOut.WS, execReq, nil, commons.UPDATE_WAIT)
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

func (s *SimulationService) executeShuffle() error {
	inReceipts := make(map[int]map[string]*core.OpcodeReceipt)

	// Get state
	gcs, err := s.stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return err
	}

	// Initialize transaction
	m1 := monitor.NewTimeMeasure("shuffle_inittxn")
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}
	itReply, err := s.execCl.InitTransaction(s.rdata, cdata, "finalizewf", "shuffle")
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
	m2 := monitor.NewTimeMeasure("shuffle_exec_1")
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
	m2.Record()

	// Step 2: shuffle
	m3 := monitor.NewTimeMeasure("shuffle_shuffle")
	var prepShOut evotingpc.PrepShufOutput
	err = protobuf.Decode(execReply.Output.Data, &prepShOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	shReply, err := s.shCl.Shuffle(prepShOut.Input.Pairs, prepShOut.Input.H, execReq)
	if err != nil {
		log.Errorf("shuffle: %v", err)
		return err
	}
	m3.Record()

	// Step 3: exec
	m4 := monitor.NewTimeMeasure("shuffle_exec_2")
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
	inReceipts[execReq.Index] = shReply.InputReceipts
	execReq.Index = 2
	execReq.OpReceipts = shReply.OutputReceipts
	execReply, err = s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing prepare_proofs_pc: %v", err)
		return err
	}
	m4.Record()

	// Step 4: update_state
	m5 := monitor.NewTimeMeasure("shuffle_update")
	var prepPrOut evotingpc.PrepProofsOutput
	err = protobuf.Decode(execReply.Output.Data, &prepPrOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	inReceipts[execReq.Index] = execReply.InputReceipts
	execReq.Index = 3
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = s.stCl.UpdateState(prepPrOut.WS, execReq, inReceipts, commons.UPDATE_WAIT)
	if err != nil {
		log.Errorf("updating state: %v", err)
		return err
	}

	_, err = s.stCl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, commons.PROOF_WAIT)
	if err != nil {
		log.Errorf("wait proof: %v", err)
	}
	m5.Record()
	return err
}

func (s *SimulationService) executeTally() error {
	inReceipts := make(map[int]map[string]*core.OpcodeReceipt)

	// Get state
	gcs, err := s.stCl.GetState(s.CID)
	if err != nil {
		log.Errorf("getting state: %v", err)
		return err
	}

	// Initialize transaction
	m1 := monitor.NewTimeMeasure("tally_inittxn")
	cdata := &execbase.ByzData{IID: s.CID, Proof: gcs.Proof.Proof,
		Genesis: s.contractGen}
	itReply, err := s.execCl.InitTransaction(s.rdata, cdata, "finalizewf", "tally")
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
	m2 := monitor.NewTimeMeasure("tally_exec_1")
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
	m2.Record()

	// Step 2: decrypt
	m3 := monitor.NewTimeMeasure("tally_decrypt")
	var prepDecOut evotingpc.PrepDecOutput
	err = protobuf.Decode(execReply.Output.Data, &prepDecOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	decReply, err := s.thCl.Decrypt(&prepDecOut.Input, execReq)
	if err != nil {
		log.Errorf("decrypting: %v", err)
		return err
	}
	m3.Record()

	// Step 3: exec
	m4 := monitor.NewTimeMeasure("tally_exec_2")
	tallyIn := evotingpc.TallyInput{
		CandCount: s.NumCandidates,
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
	inReceipts[execReq.Index] = decReply.InputReceipts
	execReq.Index = 2
	execReq.OpReceipts = decReply.OutputReceipts
	execReply, err = s.execCl.Execute(execInput, execReq)
	if err != nil {
		log.Errorf("executing tally_pc: %v", err)
		return err
	}
	m4.Record()

	// Step 4: update_state
	m5 := monitor.NewTimeMeasure("tally_update")
	var tallyOut evotingpc.TallyOutput
	err = protobuf.Decode(execReply.Output.Data, &tallyOut)
	if err != nil {
		log.Errorf("protobuf decode: %v", err)
		return err
	}
	inReceipts[execReq.Index] = execReply.InputReceipts
	execReq.Index = 3
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = s.stCl.UpdateState(tallyOut.WS, execReq, inReceipts, commons.UPDATE_WAIT)
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

func (s *SimulationService) runEvoting() error {
	ballots := commons.GenerateBallots(s.NumCandidates, s.NumParticipants)
	schedule, err := commons.ReadSchedule(s.ScheduleFile, s.NumParticipants)
	if err != nil {
		log.Error(err)
		return err
	}
	// Initialize DFUs
	err = s.initDFUs()
	if err != nil {
		return err
	}
	_, err = s.thCl.InitDKG(&core.ExecutionRequest{EP: nil})
	if err != nil {
		log.Error(err)
		return err
	}
	kp := key.NewKeyPair(cothority.Suite)
	_, dummy := protean.GenerateMesgs(2, "dummy_shuf", kp.Public)
	_, err = s.shCl.Shuffle(dummy, kp.Public, &core.ExecutionRequest{EP: nil})
	if err != nil {
		return err
	}
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
		// vote_txn
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
						err = s.executeVote(ballots[idx], idx)
						atomic.AddInt64(&ongoing, -1)
					}(ctr)
					ctr++
				}
				wg.Wait()
				i++
			}
		}
		// lock_txn
		err = s.executeLock()
		if err != nil {
			return err
		}
		// shuffle_txn
		err = s.executeShuffle()
		if err != nil {
			return err
		}
		// tally_txn
		err = s.executeTally()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SimulationService) runBatchedEvoting() error {
	ballots := commons.GenerateBallots(s.NumCandidates, s.NumParticipants)

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
	kp := key.NewKeyPair(cothority.Suite)
	_, dummy := protean.GenerateMesgs(2, "dummy_shuf", kp.Public)
	_, err = s.shCl.Shuffle(dummy, kp.Public, &core.ExecutionRequest{EP: nil})
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
		// vote_txn
		for i := 0; i < commons.BATCH_COUNT; i++ {
			err := s.executeBatchVote(ballots[s.BatchSize*i:s.BatchSize*(i+1)], i)
			if err != nil {
				return err
			}
		}
		// lock_txn
		err = s.executeLock()
		if err != nil {
			return err
		}
		// shuffle_txn
		err = s.executeShuffle()
		if err != nil {
			return err
		}
		// tally_txn
		err = s.executeTally()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SimulationService) dummyRecords() {
	for i := s.NumParticipants; i < 1000; i++ {
		label := fmt.Sprintf("p%d_vote", i)
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
	s.threshRoster = onet.NewRoster(config.Roster.List[36:55])
	s.shufRoster = onet.NewRoster(config.Roster.List[55:])

	s.stRoster.List[0] = config.Roster.List[0]
	s.execRoster.List[0] = config.Roster.List[0]
	s.threshRoster.List[0] = config.Roster.List[0]
	s.shufRoster.List[0] = config.Roster.List[0]

	keyMap := make(map[string][]kyber.Point)
	keyMap[statebase.UID] = s.stRoster.ServicePublics(skipchain.ServiceName)
	keyMap[execbase.UID] = s.execRoster.ServicePublics(libexec.ServiceName)
	keyMap[neffbase.UID] = s.shufRoster.ServicePublics(blscosi.ServiceName)
	keyMap[thbase.UID] = s.threshRoster.ServicePublics(blscosi.ServiceName)
	s.rdata, s.threshMap, err = commons.SetupRegistry(regRoster, &s.DFUFile,
		keyMap, s.BlockTime)
	if err != nil {
		log.Error(err)
	}
	if s.Batched {
		s.BatchSize = s.NumParticipants / 10
		err = s.runBatchedEvoting()
	} else {
		err = s.runEvoting()
		s.dummyRecords()
	}
	return err
}
