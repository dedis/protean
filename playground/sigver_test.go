package playground

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

func TestSigver_Schnorr(t *testing.T) {
	// Create a new ledger and prepare for proper closing
	bct := newBCTest(t)
	defer bct.local.CloseAll()

	data := []byte("On Wisconsin")
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)

	signer := darc.NewSignerEd25519(nil, nil)
	sig, err := schnorr.Sign(cothority.Suite, signer.Ed25519.Secret, digest)
	require.Nil(t, err)

	svd := &SigVerData{
		Data:    data,
		Sig:     sig,
		Publics: []kyber.Point{signer.Ed25519.Point},
	}

	instID := bct.createInstance(t, svd)
	// Get the proof from byzcoin
	pr, err := bct.cl.WaitProof(instID, bct.gMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(instID.Slice()))

	// Get the raw values of the proof.
	_, val, _, _, err := pr.KeyValue()
	require.Nil(t, err)
	// And decode the buffer to a KeyValueData
	st := SigVerStorage{}
	err = protobuf.Decode(val, &st)
	require.Nil(t, err)
	for _, s := range st.Storage {
		require.Equal(t, data, s.Data)
		require.Equal(t, sig, s.Sig)
		require.Equal(t, signer.Ed25519.Point.String(), s.Publics[0].String())
	}
}

func TestSigver_BlsCosi(t *testing.T) {
	bct := newBCTest(t)
	defer bct.local.CloseAll()

	var ds [][]byte
	var sigs [][]byte

	data := []byte("On Wisconsin")
	ds = append(ds, data)
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)

	signer := darc.NewSignerEd25519(nil, nil)
	sig, err := schnorr.Sign(cothority.Suite, signer.Ed25519.Secret, digest)
	require.Nil(t, err)
	sigs = append(sigs, sig)

	svd := &SigVerData{
		Data:    data,
		Sig:     sig,
		Publics: []kyber.Point{signer.Ed25519.Point},
	}

	instID := bct.createInstance(t, svd)
	// Get the proof from byzcoin
	pr, err := bct.cl.WaitProof(instID, bct.gMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(instID.Slice()))

	// Get the raw values of the proof.
	_, val, _, _, err := pr.KeyValue()
	require.Nil(t, err)
	// And decode the buffer to a KeyValueData
	st := SigVerStorage{}
	err = protobuf.Decode(val, &st)
	require.Nil(t, err)
	for i, s := range st.Storage {
		require.Equal(t, ds[i], s.Data)
		require.Equal(t, sigs[i], s.Sig)
		//require.Equal(t, signer.Ed25519.Point.String(), s.Publics[0].String())
	}

	cl := blscosi.NewClient()

	msg := []byte("Hello, my name is Elder Matumbo")
	ds = append(ds, msg)
	h = sha256.New()
	h.Write(msg)
	digest = h.Sum(nil)

	reply, err := cl.SignatureRequest(bct.roster, digest)
	log.Info("Error is", err)
	require.Nil(t, err)
	publics := bct.roster.ServicePublics(blscosi.ServiceName)
	//res := respBuf.(*blscosi.SignatureResponse)
	svd2 := &SigVerData{
		Data:    msg,
		Sig:     reply.Signature,
		Publics: publics,
	}
	sigs = append(sigs, reply.Signature)
	bct.updateInstance(t, instID, svd2)
	// Get the proof from byzcoin
	pr2, err := bct.cl.WaitProof(instID, bct.gMsg.BlockInterval*2, nil)
	require.Nil(t, err)

	// Get the raw values of the proof.
	_, val2, _, _, err := pr2.KeyValue()
	require.Nil(t, err)
	// And decode the buffer to a KeyValueData
	svs := SigVerStorage{}
	err = protobuf.Decode(val2, &svs)
	require.Nil(t, err)
	for i, s := range svs.Storage {
		require.Equal(t, ds[i], s.Data)
		require.Equal(t, sigs[i], s.Sig)
	}
}

// bcTest is used here to provide some simple test structure for different
// tests.
type bcTest struct {
	local    *onet.LocalTest
	services []*blscosi.Service
	signer   darc.Signer
	servers  []*onet.Server
	roster   *onet.Roster
	cl       *byzcoin.Client
	gMsg     *byzcoin.CreateGenesisBlock
	gDarc    *darc.Darc
	ct       uint64
}

func newBCTest(t *testing.T) (out *bcTest) {
	out = &bcTest{}
	// First create a local test environment with three nodes.
	out.local = onet.NewTCPTest(cothority.Suite)
	out.signer = darc.NewSignerEd25519(nil, nil)
	out.servers, out.roster, _ = out.local.GenTree(4, true)

	//services := out.local.GetServices(out.servers, blscosi.ServiceID)
	//for _, ser := range services {
	//out.services = append(out.services, ser.(*blscosi.Service))
	//}

	// Then create a new ledger with the genesis darc having the right
	// to create and update keyValue contracts.
	var err error
	out.gMsg, err = byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, out.roster,
		[]string{"spawn:" + ContractSigVerID, "invoke:" + ContractSigVerID + ".bls"}, out.signer.Identity())
	require.Nil(t, err)
	out.gDarc = &out.gMsg.GenesisDarc

	// This BlockInterval is good for testing, but in real world applications this
	// should be more like 5 seconds.
	out.gMsg.BlockInterval = time.Second * 15

	out.cl, _, err = byzcoin.NewLedger(out.gMsg, false)
	require.Nil(t, err)
	out.ct = 1

	return out
}

func (bct *bcTest) Close() {
	bct.local.CloseAll()
}

func (bct *bcTest) createInstance(t *testing.T, svd *SigVerData) byzcoin.InstanceID {
	buf, err := protobuf.Encode(svd)
	require.Nil(t, err)
	args := byzcoin.Arguments{
		{
			Name:  "request",
			Value: buf,
		},
	}
	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID:    byzcoin.NewInstanceID(bct.gDarc.GetBaseID()),
			SignerCounter: []uint64{bct.ct},
			Spawn: &byzcoin.Spawn{
				ContractID: ContractSigVerID,
				Args:       args,
			},
		}},
	}
	bct.ct++
	// And we need to sign the instruction with the signer that has his
	// public key stored in the darc.
	require.NoError(t, ctx.FillSignersAndSignWith(bct.signer))

	// Sending this transaction to ByzCoin does not directly include it in the
	// global state - first we must wait for the new block to be created.
	_, err = bct.cl.AddTransactionAndWait(ctx, 5)
	require.Nil(t, err)
	return ctx.Instructions[0].DeriveID("")
}

func (bct *bcTest) updateInstance(t *testing.T, instID byzcoin.InstanceID, svd *SigVerData) {
	buf, err := protobuf.Encode(svd)
	require.Nil(t, err)
	args := byzcoin.Arguments{
		{
			Name:  "request",
			Value: buf,
		},
	}
	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID:    instID,
			SignerCounter: []uint64{bct.ct},
			Invoke: &byzcoin.Invoke{
				ContractID: ContractSigVerID,
				Command:    "bls",
				Args:       args,
			},
		}},
	}
	bct.ct++
	// And we need to sign the instruction with the signer that has his
	// public key stored in the darc.
	require.NoError(t, ctx.FillSignersAndSignWith(bct.signer))

	// Sending this transaction to ByzCoin does not directly include it in the
	// global state - first we must wait for the new block to be created.
	_, err = bct.cl.AddTransactionAndWait(ctx, 5)
	require.Nil(t, err)
}
