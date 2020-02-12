package pristore

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/dedis/protean/compiler"
	"github.com/dedis/protean/libtest"
	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

var uname string
var aname string
var wname string
var rname string

func init() {
	uname = "../units.json"
	//flag.StringVar(&uname, "unit", "", "JSON file")
	//flag.StringVar(&aname, "admin", "", "JSON file")
	//flag.StringVar(&wname, "write", "", "JSON file")
	//flag.StringVar(&rname, "read", "", "JSON file")
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func Test_Multiple(t *testing.T) {
	aname = "./testdata/admin.json"
	wname = "./testdata/write.json"
	rname = "./testdata/read.json"
	total := 14
	compTotal := total / 2
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(total, true)
	defer local.CloseAll()
	compRoster := onet.NewRoster(roster.List[:compTotal])
	unitRoster := onet.NewRoster(roster.List[compTotal:])

	units, err := sys.PrepareUnits(unitRoster, &uname)
	require.Nil(t, err)

	err = libtest.InitCompilerUnit(local, compTotal, compRoster, hosts[:compTotal], units)
	require.NoError(t, err)
	compCl := compiler.NewClient(compRoster)
	reply, err := compCl.GetDirectoryInfo()
	require.NoError(t, err)
	directory := reply.Directory

	pristoreSvcs := local.GetServices(hosts[compTotal:], priStoreID)
	root := pristoreSvcs[0].(*Service)
	unitName := strings.Replace(ServiceName, "Service", "", 1)
	val := directory[unitName]
	txns := utils.ReverseMap(val.Txns)

	cfg := utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, unitName, txns, 10)
	initReply, err := root.InitUnit(&InitUnitRequest{Cfg: cfg})
	require.Nil(t, err)
	for _, svc := range pristoreSvcs {
		who := svc.(*Service)
		_, err := who.Authorize(&AuthorizeRequest{Request: &calypso.Authorise{ByzCoinID: initReply.ID}})
		require.NoError(t, err)
	}

	//////// ADMIN WORKFLOW BEGIN ////////
	adminWf, err := compiler.PrepareWorkflow(&aname, directory)
	require.NoError(t, err)
	require.True(t, len(adminWf.Nodes) > 0)
	planReply, err := compCl.GenerateExecutionPlan(adminWf)
	require.NoError(t, err)
	require.NotNil(t, planReply.ExecPlan.UnitPublics)
	require.NotNil(t, planReply.Signature)

	psCl := NewClient(unitRoster)
	ed := compiler.PrepareExecutionData(planReply)

	// Admin (client) setting up Calyspo
	ltsReply, err := psCl.CreateLTS(unitRoster, 2, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = ltsReply.Sig
	ed.Index++

	writers := generateWriters(2)
	readers := generateReaders(1)
	darc1 := CreateDarc(readers[0].Identity(), "provider1")
	err = AddWriteRule(darc1, writers...)
	require.NoError(t, err)
	err = AddReadRule(darc1, readers...)
	require.NoError(t, err)
	sdReply, err := psCl.SpawnDarc(*darc1, 2, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = sdReply.Sig
	ed.Index++
	psCl.Close()
	//////// ADMIN WORKFLOW END ////////

	//////// WRITE WORKFLOW BEGIN ////////
	writeWf, err := compiler.PrepareWorkflow(&wname, directory)
	require.NoError(t, err)
	require.True(t, len(writeWf.Nodes) > 0)
	writePlan, err := compCl.GenerateExecutionPlan(writeWf)
	require.NoError(t, err)
	require.NotNil(t, writePlan.ExecPlan.UnitPublics)
	require.NotNil(t, writePlan.Signature)

	psCl = NewClient(unitRoster)
	//ed = &sys.ExecutionData{
	//Index:       0,
	//ExecPlan:    writePlan.ExecPlan,
	//ClientSigs:  nil,
	//CompilerSig: writePlan.Signature,
	//UnitSigs:    make([]protocol.BlsSignature, len(writePlan.ExecPlan.Workflow.Nodes)),
	//}
	ed = compiler.PrepareExecutionData(writePlan)

	data := []byte("mor daglar")
	data2 := []byte("i remember mom")
	require.NoError(t, err)
	wr1, err := psCl.AddWrite(ltsReply.Reply.InstanceID, data, ltsReply.Reply.X, writers[0], 1, *darc1, 0, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = wr1.Sig
	ed.Index++
	wr2, err := psCl.AddWrite(ltsReply.Reply.InstanceID, data2, ltsReply.Reply.X, writers[1], 1, *darc1, 2, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = wr2.Sig
	ed.Index++

	wpr1, err := psCl.GetProof(wr1.InstanceID, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = wpr1.Sig
	ed.Index++
	wpr2, err := psCl.GetProof(wr2.InstanceID, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = wpr2.Sig
	ed.Index++
	psCl.Close()
	//////// WRITE WORKFLOW END ////////

	//////// READ WORKFLOW END ////////
	readWf, err := compiler.PrepareWorkflow(&rname, directory)
	require.NoError(t, err)
	require.True(t, len(readWf.Nodes) > 0)
	readPlan, err := compCl.GenerateExecutionPlan(readWf)
	require.NoError(t, err)
	require.NotNil(t, readPlan.ExecPlan.UnitPublics)
	require.NotNil(t, readPlan.Signature)

	psCl = NewClient(unitRoster)
	ed = compiler.PrepareExecutionData(readPlan)

	readerCt := uint64(1)
	//r1, err := psCl.AddRead(&wpr1.Proof, readers[0], readerCt, 0, ed)
	r1, err := psCl.AddRead(&wpr1.ProofResp.Proof, readers[0], readerCt, 0, ed)
	require.NoError(t, err)
	readerCt++
	ed.UnitSigs[ed.Index] = r1.Sig
	ed.Index++
	//r2, err := psCl.AddRead(&wpr2.Proof, readers[0], readerCt, 2, ed)
	r2, err := psCl.AddRead(&wpr2.ProofResp.Proof, readers[0], readerCt, 2, ed)
	require.NoError(t, err)
	readerCt++
	ed.UnitSigs[ed.Index] = r2.Sig
	ed.Index++

	rpr1, err := psCl.GetProof(r1.InstanceID, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = rpr1.Sig
	ed.Index++
	rpr2, err := psCl.GetProof(r2.InstanceID, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = rpr2.Sig
	ed.Index++
	//require.True(t, rpr1.Proof.InclusionProof.Match(r1.InstanceID.Slice()))
	//require.True(t, rpr2.Proof.InclusionProof.Match(r2.InstanceID.Slice()))
	require.True(t, rpr1.ProofResp.Proof.InclusionProof.Match(r1.InstanceID.Slice()))
	require.True(t, rpr2.ProofResp.Proof.InclusionProof.Match(r2.InstanceID.Slice()))

	//dr1, err := psCl.Decrypt(wpr1.Proof, rpr1.Proof, ed)
	dr1, err := psCl.Decrypt(&wpr1.ProofResp.Proof, &rpr1.ProofResp.Proof, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = rpr2.Sig
	ed.Index++
	//dr2, err := psCl.Decrypt(wpr2.Proof, rpr2.Proof, ed)
	dr2, err := psCl.Decrypt(&wpr2.ProofResp.Proof, &rpr2.ProofResp.Proof, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = rpr2.Sig
	ed.Index++
	//////// READ WORKFLOW END ////////

	//_, err = root.Decrypt(&DecryptRequest{Request: &calypso.DecryptKey{
	//Read:  rpr2.Proof,
	//Write: wpr1.Proof,
	//}})
	//require.Error(t, err)
	//_, err = root.Decrypt(&DecryptRequest{Request: &calypso.DecryptKey{
	//Read:  rpr1.Proof,
	//Write: wpr2.Proof,
	//}})
	//require.Error(t, err)

	pt1, err := dr1.RecoverKey(readers[0])
	require.True(t, bytes.Equal(pt1, data))
	require.NoError(t, err)
	pt2, err := dr2.RecoverKey(readers[0])
	require.True(t, bytes.Equal(pt2, data2))
	require.NoError(t, err)
	fmt.Println(string(pt1), string(pt2))
}

func prepareReadTransaction(proof *byzcoin.Proof, signer darc.Signer, signerCtr uint64) (byzcoin.ClientTransaction, error) {
	var ctx byzcoin.ClientTransaction
	instID := proof.InclusionProof.Key()
	read := &calypso.Read{
		Write: byzcoin.NewInstanceID(instID),
		Xc:    signer.Ed25519.Point,
	}
	readBuf, err := protobuf.Encode(read)
	if err != nil {
		log.Errorf("Protobuf encode error: %v", err)
		return ctx, err
	}
	ctx = byzcoin.NewClientTransaction(byzcoin.CurrentVersion, byzcoin.Instruction{
		InstanceID: byzcoin.NewInstanceID(instID),
		Spawn: &byzcoin.Spawn{
			ContractID: calypso.ContractReadID,
			Args:       byzcoin.Arguments{{Name: "read", Value: readBuf}},
		},
		SignerCounter: []uint64{signerCtr},
	})
	err = ctx.FillSignersAndSignWith(signer)
	if err != nil {
		log.Errorf("Sign transaction failed: %v", err)
		return ctx, err
	}
	return ctx, nil
}

func generateWriters(count int) []darc.Signer {
	writers := make([]darc.Signer, count)
	for i := 0; i < count; i++ {
		writers[i] = darc.NewSignerEd25519(nil, nil)
	}
	return writers
}

func generateReaders(count int) []darc.Signer {
	readers := make([]darc.Signer, count)
	for i := 0; i < count; i++ {
		readers[i] = darc.NewSignerEd25519(nil, nil)
	}
	return readers
}
