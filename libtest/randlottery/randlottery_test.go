package randlottery

import (
	"flag"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyrand"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	"github.com/dedis/protean/libexec/apps/randlottery"
	execbase "github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/libstate"
	"github.com/dedis/protean/libtest"
	"github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
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
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func Test_RandLottery(t *testing.T) {
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
	participants := libtest.GenerateWriters(10)

	// Initialize DFUs
	adminCl, err := libtest.SetupStateUnit(dfuRoster)
	require.NoError(t, err)
	execCl := libexec.NewClient(dfuRoster)
	_, err = execCl.InitUnit()
	require.NoError(t, err)
	randCl := easyrand.NewClient(dfuRoster)
	randCl.InitUnit()
	_, err = randCl.InitDKG()
	require.NoError(t, err)

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
		CodeHash:  []byte("codehash"),
		Lock:      nil,
		CurrState: fsm.InitialState,
	}

	// Initialize contract (state unit)
	tickets := randlottery.Tickets{}
	buf, err := protobuf.Encode(&tickets)
	require.NoError(t, err)
	args := byzcoin.Arguments{{Name: "tickets", Value: buf}}
	reply, err := adminCl.Cl.InitContract(raw, hdr, args, 10)
	time.Sleep(5 * time.Second)
	cid := reply.CID
	require.NoError(t, err)
	stGenesis, err := adminCl.Cl.FetchGenesisBlock(reply.TxResp.Proof.
		Latest.SkipChainID())
	require.NoError(t, err)
	require.NotNil(t, reply.TxResp.Proof)
	gcs, err := adminCl.Cl.GetState(cid)
	require.NoError(t, err)
	rdata := execbase.ByzData{
		IID:     rid,
		Proof:   *regPr,
		Genesis: *regGenesis,
	}
	cdata := execbase.ByzData{
		IID:     cid,
		Proof:   gcs.Proof.Proof,
		Genesis: *stGenesis,
	}

	d := JoinData{
		adminCl: adminCl,
		execCl:  execCl,
		rdata:   &rdata,
		cdata:   &cdata,
		cid:     cid,
	}

	// execute join txns
	executeJoin(t, &d, participants[0])
	executeJoin(t, &d, participants[1])
	executeJoin(t, &d, participants[2])
	executeJoin(t, &d, participants[3])
	executeJoin(t, &d, participants[4])

	// execute close txn
	gcs, err = adminCl.Cl.GetState(cid)
	require.NoError(t, err)
	cdata.Proof = gcs.Proof.Proof

	itReply, err := execCl.InitTransaction(rdata, cdata, "closewf", "close")
	require.NoError(t, err)
	require.NotNil(t, itReply)

	// Step 1: exec
	closeInput := randlottery.CloseInput{
		Barrier: 0,
	}
	data, err := protobuf.Encode(&closeInput)
	require.NoError(t, err)
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
	execReply, err := execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 2: update_state
	var closeOut randlottery.CloseOutput
	err = protobuf.Decode(execReply.Output.Data, &closeOut)
	require.NoError(t, err)

	execReq.Index = 1
	execReq.OpReceipts = execReply.Receipts
	_, err = adminCl.Cl.UpdateState(closeOut.WS, execReq, 5)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	//finalize txn
	gcs, err = adminCl.Cl.GetState(cid)
	require.NoError(t, err)
	cdata.Proof = gcs.Proof.Proof

	itReply, err = execCl.InitTransaction(rdata, cdata, "finalizewf", "finalize")
	require.NoError(t, err)
	require.NotNil(t, itReply)
	execReq = &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}

	// Step 1: randomness
	randReply, err := randCl.Randomness(0, execReq)
	require.NoError(t, err)

	// Step 2: exec
	finalizeInput := randlottery.FinalizeInput{
		Round:      0,
		Randomness: randReply.Output,
	}
	data, err = protobuf.Encode(&finalizeInput)
	require.NoError(t, err)
	sp = make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput = execbase.ExecuteInput{
		FnName:      "finalize_randlot",
		Data:        data,
		StateProofs: sp,
	}
	execReq.Index = 1
	execReq.OpReceipts = randReply.Receipts

	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 3: update_state
	var finalOut randlottery.FinalizeOutput
	err = protobuf.Decode(execReply.Output.Data, &finalOut)
	require.NoError(t, err)

	execReq.Index = 2
	execReq.OpReceipts = execReply.Receipts
	_, err = adminCl.Cl.UpdateState(finalOut.WS, execReq, 5)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)
}

func executeJoin(t *testing.T, d *JoinData, p darc.Signer) {
	gcs, err := d.adminCl.Cl.GetState(d.cid)
	require.NoError(t, err)

	d.cdata.Proof = gcs.Proof.Proof
	itReply, err := d.execCl.InitTransaction(*d.rdata, *d.cdata, "joinwf", "join")
	require.NoError(t, err)
	require.NotNil(t, itReply)

	// Step 1: execute
	pkHash, err := utils.HashPoint(p.Ed25519.Point)
	require.NoError(t, err)
	sig, err := p.Ed25519.Sign(pkHash)
	require.NoError(t, err)
	input := randlottery.JoinInput{Ticket: randlottery.Ticket{
		Key: p.Ed25519.Point,
		Sig: sig,
	}}
	data, err := protobuf.Encode(&input)
	require.NoError(t, err)
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
	execReply, err := d.execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 2: update_state
	var joinOut randlottery.JoinOutput
	err = protobuf.Decode(execReply.Output.Data, &joinOut)
	require.NoError(t, err)

	execReq.Index = 1
	execReq.OpReceipts = execReply.Receipts
	_, err = d.adminCl.Cl.UpdateState(joinOut.WS, execReq, 5)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)
}
