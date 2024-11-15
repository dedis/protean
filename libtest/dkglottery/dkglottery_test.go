package dkglottery

import (
	"crypto/rand"
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	"github.com/dedis/protean/libexec/apps/dkglottery"
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
func Test_DKGLottery(t *testing.T) {
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
	adminCl, byzID, err := libtest.SetupStateUnit(dfuRoster, 5)
	require.NoError(t, err)
	execCl := libexec.NewClient(dfuRoster)
	_, err = execCl.InitUnit()
	require.NoError(t, err)
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
	encTickets := dkglottery.EncTickets{}
	buf, err := protobuf.Encode(&encTickets)
	require.NoError(t, err)
	args := byzcoin.Arguments{{Name: "enc_tickets", Value: buf}}
	reply, err := adminCl.Cl.InitContract(raw, hdr, args, 10)
	require.NotNil(t, reply.TxResp.Proof)
	require.NoError(t, err)

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
	setupInput := dkglottery.SetupInput{Pk: dkgReply.Output.X}
	data, err := protobuf.Encode(&setupInput)
	require.NoError(t, err)
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		FnName:      "setup_dkglot",
		Data:        data,
		StateProofs: sp,
	}
	execReq.Index = 1
	execReq.OpReceipts = dkgReply.Receipts
	execReply, err := execCl.Execute(execInput, execReq)
	require.NoError(t, err)
	// Step 3: update_state
	var setupOut dkglottery.SetupOutput
	err = protobuf.Decode(execReply.Output.Data, &setupOut)
	require.NoError(t, err)

	execReq.Index = 2
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = adminCl.Cl.UpdateState(setupOut.WS, execReq, 5)
	require.NoError(t, err)
	_, err = adminCl.Cl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, 5)
	require.NoError(t, err)

	// execute join txns
	d := JoinData{
		adminCl: adminCl,
		execCl:  execCl,
		rdata:   rdata,
		cdata:   cdata,
		cid:     cid,
	}
	tickets := generateTickets(dkgReply.Output.X, 10)
	for _, ticket := range tickets {
		executeJoin(t, &d, ticket)
	}

	// execute close txn
	gcs, err = adminCl.Cl.GetState(cid)
	require.NoError(t, err)
	cdata.Proof = gcs.Proof.Proof

	itReply, err = execCl.InitTransaction(rdata, cdata, "closewf", "close")
	require.NoError(t, err)
	require.NotNil(t, itReply)

	// Step 1: exec
	closeInput := dkglottery.CloseInput{
		Barrier: 0,
	}
	data, err = protobuf.Encode(&closeInput)
	require.NoError(t, err)
	sp = make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput = execbase.ExecuteInput{
		FnName:      "close_dkglot",
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
	var closeOut dkglottery.CloseOutput
	err = protobuf.Decode(execReply.Output.Data, &closeOut)
	require.NoError(t, err)

	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts

	// CEY
	adminCl.Cl.Close()
	newCl := libstate.NewClient(byzcoin.NewClient(byzID, *dfuRoster))

	//_, err = adminCl.Cl.UpdateState(closeOut.WS, execReq, 5)
	_, err = newCl.UpdateState(closeOut.WS, execReq, 5)
	require.NoError(t, err)

	pr, err := adminCl.Cl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, 5)
	require.NoError(t, err)

	// execute finalize txn
	//gcs, err = adminCl.Cl.GetState(cid)
	//require.NoError(t, err)
	//cdata.Proof = gcs.Proof.Proof
	cdata.Proof = pr

	itReply, err = execCl.InitTransaction(rdata, cdata, "finalizewf", "finalize")
	require.NoError(t, err)
	require.NotNil(t, itReply)
	execReq = &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}

	// Step 1: exec
	sp = make(map[string]*core.StateProof)
	gcs.Proof.Proof = pr
	sp["readset"] = &gcs.Proof
	execInput = execbase.ExecuteInput{
		FnName:      "prepare_decrypt_dkglot",
		StateProofs: sp,
	}
	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)
	// Step 2: decrypt
	var prepOut dkglottery.PrepDecOutput
	err = protobuf.Decode(execReply.Output.Data, &prepOut)
	require.NoError(t, err)
	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	decReply, err := thCl.Decrypt(&prepOut.Input, execReq)
	require.NoError(t, err)
	// Step 3: exec
	finalInput := dkglottery.FinalizeInput{Ps: decReply.Output.Ps}
	data, err = protobuf.Encode(&finalInput)
	require.NoError(t, err)
	execInput = execbase.ExecuteInput{
		FnName:      "finalize_dkglot",
		Data:        data,
		StateProofs: sp,
	}
	execReq.Index = 2
	execReq.OpReceipts = decReply.OutputReceipts
	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)
	// Step 4: update_state
	var finalOut dkglottery.FinalizeOutput
	err = protobuf.Decode(execReply.Output.Data, &finalOut)
	require.NoError(t, err)

	execReq.Index = 3
	execReq.OpReceipts = execReply.OutputReceipts
	//_, err = adminCl.Cl.UpdateState(finalOut.WS, execReq, 5)
	_, err = newCl.UpdateState(finalOut.WS, execReq, 5)
	require.NoError(t, err)
}

func executeJoin(t *testing.T, d *JoinData, ticket utils.ElGamalPair) {
	gcs, err := d.adminCl.Cl.GetState(d.cid)
	require.NoError(t, err)

	fmt.Printf("after gs: %x\n", gcs.Proof.Proof.InclusionProof.GetRoot())

	d.cdata.Proof = gcs.Proof.Proof
	itReply, err := d.execCl.InitTransaction(d.rdata, d.cdata, "joinwf", "join")
	require.NoError(t, err)
	require.NotNil(t, itReply)

	// Step 1: execute
	input := dkglottery.JoinInput{
		Ticket: dkglottery.Ticket{
			Data: ticket,
		},
	}
	data, err := protobuf.Encode(&input)
	require.NoError(t, err)
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
	execReply, err := d.execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	// Step 2: update_state
	var joinOut dkglottery.JoinOutput
	err = protobuf.Decode(execReply.Output.Data, &joinOut)
	require.NoError(t, err)

	execReq.Index = 1
	execReq.OpReceipts = execReply.OutputReceipts
	_, err = d.adminCl.Cl.UpdateState(joinOut.WS, execReq, 5)
	require.NoError(t, err)

	wp, err := d.adminCl.Cl.WaitProof(execReq.EP.CID, execReq.EP.StateRoot, 10)
	require.NoError(t, err)
	fmt.Printf("after wp: %x\n", wp.InclusionProof.GetRoot())
}

func generateTickets(X kyber.Point, count int) []utils.ElGamalPair {
	tickets := make([]utils.ElGamalPair, count)
	for i := 0; i < count; i++ {
		randBytes := make([]byte, 24)
		rand.Read(randBytes)
		tickets[i] = utils.ElGamalEncrypt(X, randBytes)
	}
	return tickets
}
