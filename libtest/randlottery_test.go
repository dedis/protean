package libtest

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyrand"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	"github.com/dedis/protean/libexec/apps/randlottery"
	execbase "github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"testing"
	"time"
)

func Test_RandLottery(t *testing.T) {
	log.SetDebugVisible(1)
	l := onet.NewTCPTest(cothority.Suite)
	_, all, _ := l.GenTree(14, true)
	defer l.CloseAll()
	regRoster := onet.NewRoster(all.List[0:4])
	dfuRoster := onet.NewRoster(all.List[4:])

	regCl, rid, regPr, err := SetupRegistry(&dfuFile, regRoster, dfuRoster)
	require.NoError(t, err)
	regGenesis, err := regCl.FetchGenesisBlock(regPr.Latest.SkipChainID())
	require.NoError(t, err)
	participants := GenerateWriters(10)

	// Initialize DFUs
	adminCl, err := SetupStateUnit(dfuRoster)
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

	hdr := &core.ContractHeader{
		Contract:  contract,
		FSM:       fsm,
		CodeHash:  []byte("codehash"),
		Lock:      nil,
		CurrState: fsm.InitialState,
	}

	// Initialize contract (state unit)
	tickets := randlottery.Tickets{}
	buf, err := protobuf.Encode(&tickets)
	require.NoError(t, err)
	args := byzcoin.Arguments{{Name: "tickets", Value: buf}}
	reply, err := adminCl.Cl.InitContract(hdr, args, adminCl.GMsg.GenesisDarc,
		10)
	time.Sleep(5 * time.Second)
	cid := reply.CID
	require.NoError(t, err)
	stGenesis, err := adminCl.Cl.FetchGenesisBlock(reply.TxResp.Proof.
		Latest.SkipChainID())
	require.NoError(t, err)
	require.NotNil(t, reply.TxResp.Proof)
	gcs, err := adminCl.Cl.GetState(cid)
	require.NoError(t, err)
	rdata := libexec.ByzData{
		IID:     rid,
		Proof:   *regPr,
		Genesis: *regGenesis,
	}
	cdata := libexec.ByzData{
		IID:     cid,
		Proof:   gcs.Proof.Proof,
		Genesis: *stGenesis,
	}

	itReply, err := execCl.InitTransaction(rdata, cdata, "joinwf", "join")
	require.NoError(t, err)
	require.NotNil(t, itReply)

	// Step 1: execute
	p := participants[0]
	pkHash, err := utils.Hash(p.Ed25519.Point)
	require.NoError(t, err)
	sig, err := p.Ed25519.Sign(pkHash)
	require.NoError(t, err)
	input := randlottery.JoinLotteryInput{Ticket: randlottery.Ticket{
		Key: p.Ed25519.Point,
		Sig: sig,
	}}
	data, err := protobuf.Encode(&input)
	require.NoError(t, err)
	sp := make(map[string]*core.StateProof)
	sp["readset"] = &gcs.Proof
	execInput := execbase.ExecuteInput{
		Data:        data,
		StateProofs: sp,
	}
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	execReply, err := execCl.Execute("join_lottery", execInput, execReq)
	require.NoError(t, err)

	var joinOut randlottery.JoinLotteryOutput
	err = protobuf.Decode(execReply.Output.Data, &joinOut)
	require.NoError(t, err)

	execReq.Index = 1
	execReq.OpReceipts = execReply.Receipts
	_, err = adminCl.Cl.UpdateState(joinOut.WS, execReq, 5)
	require.NoError(t, err)
}
