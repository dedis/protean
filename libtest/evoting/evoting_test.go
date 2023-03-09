package evoting

import (
	"flag"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyneff"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	"github.com/dedis/protean/libexec/apps/evoting"
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

func Test_Voting(t *testing.T) {
	log.SetDebugVisible(1)
	l := onet.NewTCPTest(cothority.Suite)
	_, all, _ := l.GenTree(14, true)
	defer l.CloseAll()
	regRoster := onet.NewRoster(all.List[0:4])
	dfuRoster := onet.NewRoster(all.List[4:])

	regCl, rid, regPr, err := libtest.SetupRegistry(&dfuFile, regRoster, dfuRoster)
	require.NoError(t, err)
	regGenesis, err := regCl.FetchGenesisBlock(regPr.Latest.SkipChainID())
	require.NoError(t, err)

	// Initialize DFUs
	adminCl, _, err := libtest.SetupStateUnit(dfuRoster, 5)
	require.NoError(t, err)
	execCl := libexec.NewClient(dfuRoster)
	_, err = execCl.InitUnit()
	require.NoError(t, err)
	neffCl := easyneff.NewClient(dfuRoster)
	neffCl.InitUnit()
	thCl := threshold.NewClient(dfuRoster)
	thCl.InitUnit()

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
	encBallots := evoting.EncBallots{}
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
	setupInput := evoting.SetupInput{Pk: dkgReply.Output.X}
	data, err := protobuf.Encode(&setupInput)
	require.NoError(t, err)
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "setup_vote",
		Data:        data,
		StateProofs: sp,
	}
	execReq.Index = 1
	execReq.OpReceipts = dkgReply.Receipts
	execReply, err := execCl.Execute(execInput, execReq)
	require.NoError(t, err)
	// Step 3: update_state
	var setupOut evoting.SetupOutput
	err = protobuf.Decode(execReply.Output.Data, &setupOut)
	require.NoError(t, err)

	execReq.Index = 2
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = adminCl.Cl.UpdateState(setupOut.WS, execReq, 5)
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

	executeVote(t, &d, "00100")
	executeVote(t, &d, "01000")
	executeVote(t, &d, "00001")
	executeVote(t, &d, "00001")
	executeVote(t, &d, "00100")
	executeVote(t, &d, "10000")
	executeVote(t, &d, "10000")
	executeVote(t, &d, "01000")
	executeVote(t, &d, "00100")
	executeVote(t, &d, "00010")

	// execute close txn
	gcs, err = adminCl.Cl.GetState(cid)
	require.NoError(t, err)
	cdata.Proof = gcs.Proof.Proof

	itReply, err = execCl.InitTransaction(rdata, cdata, "closewf", "close")
	require.NoError(t, err)
	require.NotNil(t, itReply)

	// Step 1: exec
	closeInput := evoting.CloseInput{
		Barrier: 0,
	}
	data, err = protobuf.Encode(&closeInput)
	require.NoError(t, err)
	sp = make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput = execbase.ExecuteInput{
		FnName:      "close_vote",
		Data:        data,
		StateProofs: sp,
	}
	execReq = &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 2: update_state
	var closeOut evoting.CloseOutput
	err = protobuf.Decode(execReply.Output.Data, &closeOut)
	require.NoError(t, err)

	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = adminCl.Cl.UpdateState(closeOut.WS, execReq, 5)
	require.NoError(t, err)

	pr, err := adminCl.Cl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, 5)
	require.NoError(t, err)

	// execute shuffle txn
	//gcs, err = adminCl.Cl.GetState(cid)
	//require.NoError(t, err)
	//cdata.Proof = gcs.Proof.Proof
	gcs.Proof.Proof = pr
	cdata.Proof = pr

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
		FnName:      "prepare_shuffle",
		StateProofs: sp,
	}
	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 2: shuffle
	var prepShOut evoting.PrepShufOutput
	err = protobuf.Decode(execReply.Output.Data, &prepShOut)
	require.NoError(t, err)

	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	shReply, err := neffCl.Shuffle(prepShOut.Input.Pairs, prepShOut.Input.H, execReq)
	require.NoError(t, err)

	// Step 3: exec
	prepPrInput := evoting.PrepProofsInput{ShProofs: shReply.Proofs}
	data, err = protobuf.Encode(&prepPrInput)
	require.NoError(t, err)
	execInput = execbase.ExecuteInput{
		FnName:      "prepare_proofs",
		Data:        data,
		StateProofs: sp,
	}
	execReq.Index = 2
	execReq.OpReceipts = shReply.OutputReceipts
	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 4: update_state
	var prepPrOut evoting.PrepProofsOutput
	err = protobuf.Decode(execReply.Output.Data, &prepPrOut)
	require.NoError(t, err)

	execReq.Index = 3
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = adminCl.Cl.UpdateState(prepPrOut.WS, execReq, 5)

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
		FnName:      "prepare_decrypt_vote",
		StateProofs: sp,
	}
	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 2: decrypt
	var prepDecOut evoting.PrepDecOutput
	err = protobuf.Decode(execReply.Output.Data, &prepDecOut)
	require.NoError(t, err)

	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	decReply, err := thCl.Decrypt(&prepDecOut.Input, execReq)
	require.NoError(t, err)

	// Step 3: exec
	tallyIn := evoting.TallyInput{
		CandCount: 5,
		Ps:        decReply.Output.Ps,
	}
	data, err = protobuf.Encode(&tallyIn)
	require.NoError(t, err)
	execInput = execbase.ExecuteInput{
		FnName:      "tally",
		Data:        data,
		StateProofs: sp,
	}
	execReq.Index = 2
	execReq.OpReceipts = decReply.OutputReceipts
	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 4: update_state
	var tallyOut evoting.TallyOutput
	err = protobuf.Decode(execReply.Output.Data, &tallyOut)
	require.NoError(t, err)

	execReq.Index = 3
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = adminCl.Cl.UpdateState(tallyOut.WS, execReq, 5)
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
	input := evoting.VoteInput{
		Ballot: evoting.Ballot{Data: encBallot},
	}
	data, err := protobuf.Encode(&input)
	require.NoError(t, err)
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "vote",
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
	var voteOut evoting.VoteOutput
	err = protobuf.Decode(execReply.Output.Data, &voteOut)
	require.NoError(t, err)

	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = d.adminCl.Cl.UpdateState(voteOut.WS, execReq, 5)
	require.NoError(t, err)

	_, err = d.adminCl.Cl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, 5)
	require.NoError(t, err)
}
