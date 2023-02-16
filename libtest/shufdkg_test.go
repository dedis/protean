package libtest

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
	"github.com/dedis/protean/libstate"
	"github.com/dedis/protean/registry"
	"github.com/dedis/protean/threshold"
	threshbase "github.com/dedis/protean/threshold/base"
	protean "github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"os"
	"strconv"
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

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func setupRegistry(regRoster *onet.Roster, dfuRoster *onet.Roster) (*registry.
	Client, byzcoin.InstanceID, *byzcoin.Proof, error) {
	var id byzcoin.InstanceID
	dfuReg, err := libclient.ReadDFUJSON(&dfuFile)
	if err != nil {
		return nil, id, nil, err
	}
	for k := range dfuReg.Units {
		//dfuReg.Units[k].Keys = roster.Publics()
		if k == "easyneff" || k == "threshold" || k == "easyrand" {
			dfuReg.Units[k].Keys = dfuRoster.ServicePublics(blscosi.ServiceName)
		} else if k == "codeexec" {
			dfuReg.Units[k].Keys = dfuRoster.ServicePublics(libexec.ServiceName)
		} else if k == "state" {
			dfuReg.Units[k].Keys = dfuRoster.ServicePublics(libstate.ServiceName)
		} else {
			os.Exit(1)
		}
	}

	adminCl, byzID, err := registry.SetupByzcoin(regRoster, 1)
	if err != nil {
		return nil, id, nil, err
	}
	reply, err := adminCl.InitRegistry(dfuReg, 3)
	if err != nil {
		return nil, id, nil, err
	}
	pr, err := adminCl.Cl.WaitProof(reply.IID, 2*time.Second, nil)
	if err != nil {
		return nil, id, nil, err
	}

	bc := byzcoin.NewClient(byzID, *regRoster)
	cl := registry.NewClient(bc)
	return cl, reply.IID, pr, nil
}

func setupStateUnit(roster *onet.Roster) (*libstate.AdminClient, error) {
	adminCl, byzID, err := libstate.SetupByzcoin(roster, 1)
	if err != nil {
		return nil, err
	}
	req := &libstate.InitUnitRequest{
		ByzID:  byzID,
		Roster: roster,
	}
	_, err = adminCl.Cl.InitUnit(req)
	if err != nil {
		return nil, err
	}
	return adminCl, nil
}

func Test_ShufDKG(t *testing.T) {
	log.SetDebugVisible(1)
	l := onet.NewTCPTest(cothority.Suite)
	_, all, _ := l.GenTree(14, true)
	defer l.CloseAll()
	regRoster := onet.NewRoster(all.List[0:4])
	dfuRoster := onet.NewRoster(all.List[4:])

	regCl, rid, regPr, err := setupRegistry(regRoster, dfuRoster)
	require.NoError(t, err)
	regGenesis, err := regCl.FetchGenesisBlock(regPr.Latest.SkipChainID())
	require.NoError(t, err)

	// Initialize DFUs
	adminCl, err := setupStateUnit(dfuRoster)
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

	hdr := &core.ContractHeader{
		Contract:  contract,
		FSM:       fsm,
		CodeHash:  []byte("codehash"),
		Lock:      nil,
		CurrState: fsm.InitialState,
	}

	// Initialize contract (state unit)
	reply, err := adminCl.Cl.InitContract(hdr, adminCl.GMsg.GenesisDarc, 10)
	cid := reply.CID
	require.NoError(t, err)
	stGenesis, err := adminCl.Cl.FetchGenesisBlock(reply.TxResp.Proof.
		Latest.SkipChainID())
	require.NoError(t, err)
	require.NotNil(t, reply.TxResp.Proof)
	gcs, err := adminCl.Cl.GetContractState(cid)
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
	pairs, _ := generateRequest(5, cleartext, dkgReply.X)
	input := shufdkg.PrepareShufInput{Pairs: pairs}
	data, err := protobuf.Encode(&input)
	require.NoError(t, err)
	execInput := execbase.ExecuteInput{
		Data: data,
	}
	execReply, err := execCl.Execute("prep_shuf", execInput, execReq)
	require.NoError(t, err)

	var shInput neffbase.ShuffleInput
	err = protobuf.Decode(execReply.Output.Data, &shInput)
	require.NoError(t, err)

	// Step 3: Shuffle ciphertexts
	execReq.Index = 2
	execReq.OpReceipts = execReply.Receipts
	shufReply, err := neffCl.Shuffle(shInput.Pairs, dkgReply.X, execReq)
	require.NoError(t, err)

	// Step 4: Execute code (prepare inputs for decryption)
	execReq.Index = 3
	execReq.OpReceipts = shufReply.Receipts
	dInput := shufdkg.PrepareDecInput{ShufProof: shufReply.Proofs}
	data, err = protobuf.Encode(&dInput)
	require.NoError(t, err)
	execInput.Data = data
	execReply, err = execCl.Execute("prep_dec", execInput, execReq)
	require.NoError(t, err)

	var decInput threshbase.DecryptInput
	err = protobuf.Decode(execReply.Output.Data, &decInput)
	require.NoError(t, err)

	// Step 5: Decrypt
	execReq.Index = 4
	execReq.OpReceipts = execReply.Receipts
	decReply, err := thClient.Decrypt(&decInput, execReq)
	require.NoError(t, err)

	for _, p := range decReply.Ps {
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
