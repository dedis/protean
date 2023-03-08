package shufdkg

import (
	"flag"
	"fmt"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyneff"
	neffbase "github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	"github.com/dedis/protean/libexec/apps/shufdkg"
	execbase "github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/libtest"
	"github.com/dedis/protean/threshold"
	threshbase "github.com/dedis/protean/threshold/base"
	protean "github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"strconv"
	"testing"
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

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func Test_ShufDKG(t *testing.T) {
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
	thClient := threshold.NewClient(dfuRoster)
	_, err = thClient.InitUnit()
	require.NoError(t, err)
	neffCl := easyneff.NewClient(dfuRoster)
	neffCl.InitUnit()

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
		CodeHash:  protean.GetCodeHash(),
		Lock:      false,
		CurrState: fsm.InitialState,
	}

	// Initialize contract (state unit)
	reply, err := adminCl.Cl.InitContract(raw, hdr, nil, 10)
	cid := reply.CID
	require.NoError(t, err)
	stGenesis, err := adminCl.Cl.FetchGenesisBlock(reply.TxResp.Proof.
		Latest.SkipChainID())
	require.NoError(t, err)
	require.NotNil(t, reply.TxResp.Proof)
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

	// Step 0: Initialize transaction
	itReply, err := execCl.InitTransaction(rdata, cdata, "shufdkg", "testtxn")
	require.NoError(t, err)
	require.NotNil(t, itReply)

	// Step 1: Run DKG
	execReq := &core.ExecutionRequest{
		Index: 0,
		EP:    &itReply.Plan,
	}
	dkgReply, err := thClient.InitDKG(execReq)
	require.NoError(t, err)

	// Step 2: Execute code (prepare inputs for shuffling)
	// Use the DKG key for encryption
	execReq.Index = 1
	cleartext := "Go Badgers!"
	pairs, _ := generateRequest(5, cleartext, dkgReply.Output.X)
	input := shufdkg.PrepareShufInput{Pairs: pairs, H: dkgReply.Output.X}
	data, err := protobuf.Encode(&input)
	require.NoError(t, err)
	execInput := execbase.ExecuteInput{
		FnName: "prep_shuf",
		Data:   data,
	}
	execReply, err := execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	var shInput neffbase.ShuffleInput
	err = protobuf.Decode(execReply.Output.Data, &shInput)
	require.NoError(t, err)

	// Step 3: Shuffle ciphertexts
	execReq.Index = 2
	execReq.OpReceipts = execReply.OutputReceipts
	shufReply, err := neffCl.Shuffle(shInput.Pairs, shInput.H, execReq)
	require.NoError(t, err)

	// Step 4: Execute code (prepare inputs for decryption)
	execReq.Index = 3
	execReq.OpReceipts = shufReply.OutputReceipts
	dInput := shufdkg.PrepareDecInput{ShufProof: shufReply.Proofs}
	data, err = protobuf.Encode(&dInput)
	require.NoError(t, err)
	execInput.FnName = "prep_dec"
	execInput.Data = data
	execReply, err = execCl.Execute(execInput, execReq)
	require.NoError(t, err)

	var decInput threshbase.DecryptInput
	err = protobuf.Decode(execReply.Output.Data, &decInput)
	require.NoError(t, err)

	// Step 5: Decrypt
	execReq.Index = 4
	execReq.OpReceipts = execReply.OutputReceipts
	decReply, err := thClient.Decrypt(&decInput, execReq)
	require.NoError(t, err)

	for _, p := range decReply.Output.Ps {
		msg, err := p.Data()
		require.NoError(t, err)
		fmt.Println("Recovered message is:", string(msg))
	}

}

func generateRequest(n int, msg string, pub kyber.Point) (protean.ElGamalPairs,
	*key.Pair) {
	var kp *key.Pair
	if pub != nil {
		kp = &key.Pair{
			Public: pub,
		}
	} else {
		kp = key.NewKeyPair(cothority.Suite)
	}
	pairs := make([]protean.ElGamalPair, n)
	for i, _ := range pairs {
		pMsg := msg + strconv.Itoa(i)
		c := protean.ElGamalEncrypt(kp.Public, []byte(pMsg))
		pairs[i] = protean.ElGamalPair{K: c.K, C: c.C}
	}
	return protean.ElGamalPairs{Pairs: pairs}, kp
}
