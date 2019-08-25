package pristore

import (
	"bytes"
	"testing"
	"time"

	"github.com/dedis/protean"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestPristore_MultipleReaders(t *testing.T) {
	n := 7
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, privStoreID)
	root := services[0].(*Service)
	initReq := generateInitRequest(roster)
	initReply, err := root.InitUnit(initReq)
	require.NoError(t, err)

	for _, svc := range services {
		who := svc.(*Service)
		_, err := who.Authorize(&AuthorizeRequest{Request: &calypso.Authorise{ByzCoinID: initReply.ID}})
		require.NoError(t, err)
	}

	ltsReply, err := root.CreateLTS(&CreateLTSRequest{LTSRoster: roster, Wait: 4})
	require.NoError(t, err)

	writers := generateWriters(10)
	readers := generateReaders(1)
	darc1 := CreateDarc(readers[0].Identity(), "provider1")
	err = AddWriteRule(darc1, writers...)
	require.NoError(t, err)
	err = AddReadRule(darc1, readers...)
	require.NoError(t, err)
	_, err = root.SpawnDarc(&SpawnDarcRequest{Darc: *darc1, Wait: 4})
	require.NoError(t, err)

	data := []byte("mor daglar")
	data2 := []byte("i remember mom")
	ctx, err := prepareWriteTransaction(ltsReply, data, writers[0], 1, *darc1)
	require.NoError(t, err)
	wr1, err := root.AddWrite(&AddWriteRequest{Ctx: ctx, Wait: 4})
	ctx, err = prepareWriteTransaction(ltsReply, data2, writers[1], 1, *darc1)
	require.NoError(t, err)
	wr2, err := root.AddWrite(&AddWriteRequest{Ctx: ctx, Wait: 4})

	wpr1, err := root.GetProof(&GetProofRequest{InstanceID: wr1.InstanceID})
	require.NoError(t, err)
	wpr2, err := root.GetProof(&GetProofRequest{InstanceID: wr2.InstanceID})
	require.NoError(t, err)

	readerCt := uint64(1)
	ctx, err = prepareReadTransaction(&wpr1.Proof, readers[0], readerCt)
	require.NoError(t, err)
	r1, err := root.AddRead(&AddReadRequest{Ctx: ctx, Wait: 4})
	require.NoError(t, err)
	readerCt++
	ctx, err = prepareReadTransaction(&wpr2.Proof, readers[0], readerCt)
	require.NoError(t, err)
	r2, err := root.AddRead(&AddReadRequest{Ctx: ctx, Wait: 4})
	require.NoError(t, err)
	readerCt++

	rpr1, err := root.GetProof(&GetProofRequest{InstanceID: r1.InstanceID})
	require.NoError(t, err)
	rpr2, err := root.GetProof(&GetProofRequest{InstanceID: r2.InstanceID})
	require.NoError(t, err)
	require.True(t, rpr1.Proof.InclusionProof.Match(r1.InstanceID.Slice()))
	require.True(t, rpr2.Proof.InclusionProof.Match(r2.InstanceID.Slice()))

	dr1, err := root.Decrypt(&DecryptRequest{Request: &calypso.DecryptKey{
		Read:  rpr1.Proof,
		Write: wpr1.Proof,
	}})
	require.NoError(t, err)
	dr2, err := root.Decrypt(&DecryptRequest{Request: &calypso.DecryptKey{
		Read:  rpr2.Proof,
		Write: wpr2.Proof,
	}})
	require.NoError(t, err)

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

func generateInitRequest(roster *onet.Roster) *InitUnitRequest {
	scData := &protean.ScInitData{
		MHeight: 2,
		BHeight: 2,
	}
	uData := &protean.BaseStorage{
		UInfo: &protean.UnitInfo{
			UnitID:   "pristore",
			UnitName: "pristoreUnit",
			Txns:     map[string]string{"a": "b", "c": "d"},
		},
	}
	return &InitUnitRequest{
		Roster:       roster,
		ScData:       scData,
		BaseStore:    uData,
		BlkInterval:  10,
		DurationType: time.Second,
	}
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
