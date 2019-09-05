package pristore

import (
	"bytes"
	"flag"
	"strings"
	"testing"

	"github.com/dedis/protean/compiler"
	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"

	cliutils "github.com/dedis/protean/client/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
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
	flag.StringVar(&uname, "unit", "", "JSON file")
	flag.StringVar(&aname, "admin", "", "JSON file")
	flag.StringVar(&wname, "write", "", "JSON file")
	flag.StringVar(&rname, "read", "", "JSON file")
}

func initCompilerUnit(t *testing.T, local *onet.LocalTest, total int, roster *onet.Roster, hosts []*onet.Server, units []*sys.FunctionalUnit) {
	compServices := local.GetServices(hosts[:total], compiler.GetServiceID())
	compNodes := make([]*compiler.Service, len(compServices))
	for i := 0; i < len(compServices); i++ {
		compNodes[i] = compServices[i].(*compiler.Service)
	}
	root := compNodes[0]
	initReply, err := root.InitUnit(&compiler.InitUnitRequest{Roster: roster, ScCfg: &sys.ScConfig{MHeight: 2, BHeight: 2}})
	require.NoError(t, err)
	for _, n := range compNodes {
		_, err = n.StoreGenesis(&compiler.StoreGenesisRequest{Genesis: initReply.Genesis})
		require.NoError(t, err)
	}
	_, err = root.CreateUnits(&compiler.CreateUnitsRequest{Units: units})
	require.NoError(t, err)
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestPristore_Multiple(t *testing.T) {
	total := 14
	compTotal := total / 2
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(total, true)
	defer local.CloseAll()
	compRoster := onet.NewRoster(roster.List[:compTotal])
	unitRoster := onet.NewRoster(roster.List[compTotal:])

	units, err := sys.PrepareUnits(unitRoster, &uname)
	require.Nil(t, err)

	initCompilerUnit(t, local, compTotal, compRoster, hosts[:compTotal], units)
	compCl := compiler.NewClient(compRoster)
	reply, err := compCl.GetDirectoryInfo()
	require.NoError(t, err)
	directory := reply.Directory

	pristoreSvcs := local.GetServices(hosts[compTotal:], priStoreID)
	root := pristoreSvcs[0].(*Service)
	unitName := strings.Replace(ServiceName, "Service", "", 1)
	val := directory[unitName]
	txns := utils.ReverseMap(val.Txns)

	cfg := utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, unitName, txns)
	initReply, err := root.InitUnit(&InitUnitRequest{Cfg: cfg})
	require.Nil(t, err)
	for _, svc := range pristoreSvcs {
		who := svc.(*Service)
		_, err := who.Authorize(&AuthorizeRequest{Request: &calypso.Authorise{ByzCoinID: initReply.ID}})
		require.NoError(t, err)
	}

	//////// ADMIN WORKFLOW BEGIN ////////
	adminWf, err := cliutils.PrepareWorkflow(&aname, directory, nil, false)
	require.NoError(t, err)
	require.True(t, len(adminWf.Nodes) > 0)
	planReply, err := compCl.GenerateExecutionPlan(adminWf, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, planReply.ExecPlan.Publics)
	require.NotNil(t, planReply.Signature)

	psCl := NewClient(unitRoster)
	ed := &sys.ExecutionData{
		Index:       0,
		ExecPlan:    planReply.ExecPlan,
		ClientSigs:  nil,
		CompilerSig: planReply.Signature,
		UnitSigs:    make([]protocol.BlsSignature, len(planReply.ExecPlan.Workflow.Nodes)),
	}

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
	writeWf, err := cliutils.PrepareWorkflow(&wname, directory, nil, false)
	require.NoError(t, err)
	require.True(t, len(writeWf.Nodes) > 0)
	writePlan, err := compCl.GenerateExecutionPlan(writeWf, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, writePlan.ExecPlan.Publics)
	require.NotNil(t, writePlan.Signature)

	psCl = NewClient(unitRoster)
	ed = &sys.ExecutionData{
		Index:       0,
		ExecPlan:    writePlan.ExecPlan,
		ClientSigs:  nil,
		CompilerSig: writePlan.Signature,
		UnitSigs:    make([]protocol.BlsSignature, len(writePlan.ExecPlan.Workflow.Nodes)),
	}

	data := []byte("mor daglar")
	data2 := []byte("i remember mom")
	require.NoError(t, err)
	wr1, err := psCl.AddWrite(data, ltsReply.Reply.InstanceID, ltsReply.Reply.X, writers[0], 1, *darc1, 0, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = wr1.Sig
	ed.Index++
	wr2, err := psCl.AddWrite(data2, ltsReply.Reply.InstanceID, ltsReply.Reply.X, writers[1], 1, *darc1, 2, ed)
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
	readWf, err := cliutils.PrepareWorkflow(&rname, directory, nil, false)
	require.NoError(t, err)
	require.True(t, len(readWf.Nodes) > 0)
	readPlan, err := compCl.GenerateExecutionPlan(readWf, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, readPlan.ExecPlan.Publics)
	require.NotNil(t, readPlan.Signature)

	psCl = NewClient(unitRoster)
	ed = &sys.ExecutionData{
		Index:       0,
		ExecPlan:    readPlan.ExecPlan,
		ClientSigs:  nil,
		CompilerSig: readPlan.Signature,
		UnitSigs:    make([]protocol.BlsSignature, len(readPlan.ExecPlan.Workflow.Nodes)),
	}

	readerCt := uint64(1)
	//ctx, err = prepareReadTransaction(&wpr1.Proof, readers[0], readerCt)
	//require.NoError(t, err)
	//r1, err := root.AddRead(&AddReadRequest{Ctx: ctx, Wait: 0})
	r1, err := psCl.AddRead(&wpr1.Proof, readers[0], readerCt, 0, ed)
	require.NoError(t, err)
	readerCt++
	ed.UnitSigs[ed.Index] = r1.Sig
	ed.Index++
	//ctx, err = prepareReadTransaction(&wpr2.Proof, readers[0], readerCt)
	//require.NoError(t, err)
	//r2, err := root.AddRead(&AddReadRequest{Ctx: ctx, Wait: 2})
	r2, err := psCl.AddRead(&wpr2.Proof, readers[0], readerCt, 2, ed)
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
	require.True(t, rpr1.Proof.InclusionProof.Match(r1.InstanceID.Slice()))
	require.True(t, rpr2.Proof.InclusionProof.Match(r2.InstanceID.Slice()))

	dr1, err := psCl.Decrypt(wpr1.Proof, rpr1.Proof, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = rpr2.Sig
	ed.Index++
	dr2, err := psCl.Decrypt(wpr2.Proof, rpr2.Proof, ed)
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
	ctx = byzcoin.ClientTransaction{
		Instructions: byzcoin.Instructions{{
			InstanceID: byzcoin.NewInstanceID(instID),
			Spawn: &byzcoin.Spawn{
				ContractID: calypso.ContractReadID,
				Args:       byzcoin.Arguments{{Name: "read", Value: readBuf}},
			},
			SignerCounter: []uint64{signerCtr},
		}},
	}
	err = ctx.FillSignersAndSignWith(signer)
	if err != nil {
		return ctx, err
	}
	return ctx, nil
}

func prepareWriteTransaction(ltsReply *CreateLTSReply, data []byte, signer darc.Signer, signerCtr uint64, darc darc.Darc) (byzcoin.ClientTransaction, error) {
	var ctx byzcoin.ClientTransaction
	write := calypso.NewWrite(cothority.Suite, ltsReply.Reply.InstanceID, darc.GetBaseID(), ltsReply.Reply.X, data)
	writeBuf, err := protobuf.Encode(write)
	if err != nil {
		return ctx, err
	}
	ctx = byzcoin.ClientTransaction{
		Instructions: byzcoin.Instructions{{
			InstanceID: byzcoin.NewInstanceID(darc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: calypso.ContractWriteID,
				Args: byzcoin.Arguments{{
					Name: "write", Value: writeBuf}},
			},
			SignerCounter: []uint64{signerCtr},
		}},
	}
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
