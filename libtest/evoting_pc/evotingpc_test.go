package evotingpc

import (
	"flag"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyneff"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	evotingpc "github.com/dedis/protean/libexec/apps/evoting_pc"
	execbase "github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/libstate"
	"github.com/dedis/protean/libtest"
	"github.com/dedis/protean/threshold"
	"github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"testing"
	"time"
)

var contractFile string
var fsmFile string
var dfuFile string

var testSuite = pairing.NewSuiteBn256()

func init() {
	flag.StringVar(&contractFile, "contract", "", "JSON file")
	flag.StringVar(&fsmFile, "fsm", "", "JSON file")
	flag.StringVar(&dfuFile, "dfu", "", "JSON file")
}

type JoinData struct {
	adminCl *libstate.AdminClient
	execCl  *libexec.Client
	rdata   *execbase.ByzData
	cdata   *execbase.ByzData
	cid     byzcoin.InstanceID
	X       kyber.Point
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}
func Test_VotingPC(t *testing.T) {
	log.SetDebugVisible(1)
	l := onet.NewTCPTest(cothority.Suite)
	//_, all, _ := l.GenTree(14, true)
	//defer l.CloseAll()
	//regRoster := onet.NewRoster(all.List[0:4])
	//dfuRoster := onet.NewRoster(all.List[4:])
	_, all, _ := l.GenTree(19, true)
	defer l.CloseAll()
	regRoster := onet.NewRoster(all.List[0:4])
	byzRoster := onet.NewRoster(all.List[:])
	smallRoster := onet.NewRoster(all.List[:13])

	rosters := make(map[string]*onet.Roster)
	rosters["state"] = byzRoster
	rosters["threshold"] = byzRoster
	rosters["easyrand"] = byzRoster
	rosters["codeexec"] = smallRoster
	rosters["easyneff"] = smallRoster

	//regCl, rid, regPr, err := libtest.SetupRegistry(&dfuFile, regRoster, dfuRoster)
	regCl, rid, regPr, err := libtest.SetupRegistry(&dfuFile, regRoster, rosters)
	require.NoError(t, err)
	regGenesis, err := regCl.FetchGenesisBlock(regPr.Latest.SkipChainID())
	require.NoError(t, err)

	// Initialize DFUs
	//adminCl, _, err := libtest.SetupStateUnit(dfuRoster, 5)
	//require.NoError(t, err)
	//execCl := libexec.NewClient(dfuRoster)
	//_, err = execCl.InitUnit()
	//require.NoError(t, err)
	//neffCl := easyneff.NewClient(dfuRoster)
	//neffCl.InitUnit()
	//thCl := threshold.NewClient(dfuRoster)
	//thCl.InitUnit()
	adminCl, _, err := libtest.SetupStateUnit(byzRoster, 5)
	require.NoError(t, err)
	execCl := libexec.NewClient(smallRoster)
	_, err = execCl.InitUnit(7)
	require.NoError(t, err)
	neffCl := easyneff.NewClient(smallRoster)
	neffCl.InitUnit(7)
	thCl := threshold.NewClient(byzRoster)
	thCl.InitUnit(13)

	// Client-side operations: read JSON files
	contract, err := libclient.ReadContractJSON(&contractFile)
	require.NoError(t, err)
	fsm, err := libclient.ReadFSMJSON(&fsmFile)
	require.NoError(t, err)

	raw := &core.ContractRaw{
		Contract: contract,
		FSM:      fsm,
	}
	hdr := &core.ContractHeader{
		CodeHash:  utils.GetCodeHash(),
		Lock:      false,
		CurrState: fsm.InitialState,
	}

	// Initialize contract (state unit)
	encBallots := evotingpc.EncBallots{}
	buf, err := protobuf.Encode(&encBallots)
	require.NoError(t, err)
	args := byzcoin.Arguments{{Name: "enc_ballots", Value: buf}}
	reply, err := adminCl.Cl.InitContract(raw, hdr, args, 10)
	require.NoError(t, err)
	require.NotNil(t, reply.TxResp.Proof)

	cid := reply.CID
	stGenesis, err := adminCl.Cl.FetchGenesisBlock(reply.TxResp.Proof.
		Latest.SkipChainID())
	require.NoError(t, err)
	time.Sleep(3 * time.Second)

	gcs, err := adminCl.Cl.GetState(cid)
	require.NoError(t, err)
	rdata := &execbase.ByzData{
		IID:     rid,
		Proof:   regPr,
		Genesis: regGenesis,
	}
	cdata := &execbase.ByzData{
		IID:     cid,
		Proof:   gcs.Proof.Proof,
		Genesis: stGenesis,
	}

	// Execute setup txn
	itReply, err := execCl.InitTransaction(rdata, cdata, "setupwf", "setup")
	require.NoError(t, err)
	require.NotNil(t, itReply)
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}

	// Step 1: init_dkg
	dkgReply, err := thCl.InitDKG(execReq)
	require.NoError(t, err)
	// Step 2: exec
	setupInput := evotingpc.SetupInput{Pk: dkgReply.Output.X}
	data, err := protobuf.Encode(&setupInput)
	require.NoError(t, err)
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "setup_vote_pc",
		Data:        data,
		StateProofs: sp,
	}
	execReq.Index = 1
	execReq.OpReceipts = dkgReply.Receipts
	execReply, err := execCl.Execute(execInput, execReq)
	require.NoError(t, err)
	// Step 3: update_state
	var setupOut evotingpc.SetupOutput
	err = protobuf.Decode(execReply.Output.Data, &setupOut)
	require.NoError(t, err)

	execReq.Index = 2
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = adminCl.Cl.UpdateState(setupOut.WS, execReq, nil, 5)
	require.NoError(t, err)

	_, err = adminCl.Cl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, 5)
	require.NoError(t, err)

	d := JoinData{
		adminCl: adminCl,
		execCl:  execCl,
		rdata:   rdata,
		cdata:   cdata,
		cid:     cid,
		X:       dkgReply.Output.X,
	}

	for i := 0; i < 100; i++ {
		executeVote(t, &d, "0010000000")
	}
	//executeVote(t, &d, "00100")
	//executeVote(t, &d, "01000")
	//executeVote(t, &d, "00001")
	//executeVote(t, &d, "00001")
	//executeVote(t, &d, "00100")
	//executeVote(t, &d, "10000")
	//executeVote(t, &d, "10000")
	//executeVote(t, &d, "01000")
	//executeVote(t, &d, "00100")
	//executeVote(t, &d, "00010")

	// execute lock txn
	gcs, err = adminCl.Cl.GetState(cid)
	require.NoError(t, err)
	cdata.Proof = gcs.Proof.Proof

	itReply, err = execCl.InitTransaction(rdata, cdata, "finalizewf", "lock")
	require.NoError(t, err)
	require.NotNil(t, itReply)

	// Step 1: exec
	lockInput := evotingpc.LockInput{
		Barrier: 0,
	}
	data, err = protobuf.Encode(&lockInput)
	require.NoError(t, err)
	hBuf, err := dkgReply.Output.X.MarshalBinary()
	require.NoError(t, err)
	pc := &core.KVDict{Data: make(map[string][]byte)}
	pc.Data["h"] = hBuf
	sp = make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput = execbase.ExecuteInput{
		FnName:      "lock",
		Data:        data,
		StateProofs: sp,
		Precommits:  pc,
	}
	execReq = &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 2: update_state
	var lockOut evotingpc.LockOutput
	err = protobuf.Decode(execReply.Output.Data, &lockOut)
	require.NoError(t, err)

	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = adminCl.Cl.UpdateState(lockOut.WS, execReq, nil, 5)
	require.NoError(t, err)

	pr, err := adminCl.Cl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, 5)
	require.NoError(t, err)

	// execute shuffle txn
	//gcs, err = adminCl.Cl.GetState(cid)
	//require.NoError(t, err)
	//cdata.Proof = gcs.Proof.Proof
	cdata.Proof = pr
	gcs.Proof.Proof = pr

	itReply, err = execCl.InitTransaction(rdata, cdata, "finalizewf", "shuffle")
	require.NoError(t, err)
	require.NotNil(t, itReply)
	execReq = &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}

	// Step 1: exec
	sp = make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput = execbase.ExecuteInput{
		FnName:      "prepare_shuffle_pc",
		StateProofs: sp,
	}
	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 2: shuffle
	var prepShOut evotingpc.PrepShufOutput
	err = protobuf.Decode(execReply.Output.Data, &prepShOut)
	require.NoError(t, err)

	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	shReply, err := neffCl.Shuffle(prepShOut.Input.Pairs, prepShOut.Input.H, execReq)
	require.NoError(t, err)

	// Step 3: exec
	prepPrInput := evotingpc.PrepProofsInput{ShProofs: shReply.Proofs}
	data, err = protobuf.Encode(&prepPrInput)
	require.NoError(t, err)
	execInput = execbase.ExecuteInput{
		FnName:      "prepare_proofs_pc",
		Data:        data,
		StateProofs: sp,
	}
	log.Info("Size of shuffle proofs:", len(data))
	execReq.Index = 2
	execReq.OpReceipts = shReply.OutputReceipts
	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 4: update_state
	var prepPrOut evotingpc.PrepProofsOutput
	err = protobuf.Decode(execReply.Output.Data, &prepPrOut)
	require.NoError(t, err)

	execReq.Index = 3
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = adminCl.Cl.UpdateState(prepPrOut.WS, execReq, nil, 5)

	pr, err = adminCl.Cl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, 5)
	require.NoError(t, err)

	// execute tally txn
	//gcs, err = adminCl.Cl.GetState(cid)
	//require.NoError(t, err)
	//cdata.Proof = gcs.Proof.Proof
	cdata.Proof = pr
	gcs.Proof.Proof = pr

	itReply, err = execCl.InitTransaction(rdata, cdata, "finalizewf", "tally")
	require.NoError(t, err)
	require.NotNil(t, itReply)
	execReq = &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}

	// Step 1: exec
	sp = make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput = execbase.ExecuteInput{
		FnName:      "prepare_decrypt_vote_pc",
		StateProofs: sp,
	}
	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 2: decrypt
	var prepDecOut evotingpc.PrepDecOutput
	err = protobuf.Decode(execReply.Output.Data, &prepDecOut)
	require.NoError(t, err)
	log.Info("Input to decrypt size:", len(execReply.Output.Data),
		len(prepDecOut.Input.Pairs), prepDecOut.Input.Pairs[0].C.MarshalSize(), prepDecOut.Input.Pairs[0].K.MarshalSize())

	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	decReply, err := thCl.Decrypt(&prepDecOut.Input, execReq)
	require.NoError(t, err)

	// Step 3: exec
	tallyIn := evotingpc.TallyInput{
		CandCount: 10,
		Ps:        decReply.Output.Ps,
	}
	data, err = protobuf.Encode(&tallyIn)
	require.NoError(t, err)
	execInput = execbase.ExecuteInput{
		FnName:      "tally_pc",
		Data:        data,
		StateProofs: sp,
	}
	execReq.Index = 2
	execReq.OpReceipts = decReply.OutputReceipts
	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)
	log.Info("decrypt output size:", len(data), len(tallyIn.Ps), tallyIn.Ps[0].MarshalSize())

	// Step 4: update_state
	var tallyOut evotingpc.TallyOutput
	err = protobuf.Decode(execReply.Output.Data, &tallyOut)
	require.NoError(t, err)

	log.Info("Final size:", len(execReply.Output.Data))

	execReq.Index = 3
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = adminCl.Cl.UpdateState(tallyOut.WS, execReq, nil, 5)
	require.NoError(t, err)
}

func executeVote(t *testing.T, d *JoinData, ballot string) {
	gcs, err := d.adminCl.Cl.GetState(d.cid)
	require.NoError(t, err)

	d.cdata.Proof = gcs.Proof.Proof
	itReply, err := d.execCl.InitTransaction(d.rdata, d.cdata, "votewf",
		"vote")
	require.NoError(t, err)
	require.NotNil(t, itReply)

	// Step 1: execute
	encBallot := utils.ElGamalEncrypt(d.X, []byte(ballot))
	input := evotingpc.VoteInput{
		Ballot: evotingpc.Ballot{Data: encBallot},
	}
	data, err := protobuf.Encode(&input)
	require.NoError(t, err)
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
	execReply, err := d.execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 2: update_state
	var voteOut evotingpc.VoteOutput
	err = protobuf.Decode(execReply.Output.Data, &voteOut)
	require.NoError(t, err)

	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = d.adminCl.Cl.UpdateState(voteOut.WS, execReq, nil, 5)
	require.NoError(t, err)

	_, err = d.adminCl.Cl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, 10)
	require.NoError(t, err)
}
