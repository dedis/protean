package dummy

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/protobuf"
	"testing"
	"time"
)

func TestDummy_Invoke(t *testing.T) {
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(15, true)

	genesisMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, roster,
		[]string{"spawn:" + ContractKeyValueID, "invoke:" + ContractKeyValueID + ".update"}, signer.Identity())
	require.NoError(t, err)
	gDarc := &genesisMsg.GenesisDarc

	genesisMsg.BlockInterval = time.Second

	cl, _, err := byzcoin.NewLedger(genesisMsg, false)
	require.NoError(t, err)

	args := make(byzcoin.Arguments, 2)
	args[0] = byzcoin.Argument{Name: "key1", Value: []byte("abbas")}
	args[1] = byzcoin.Argument{Name: "key2", Value: []byte("haydar")}

	ctx, err := cl.CreateTransaction(byzcoin.Instruction{
		InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
		Spawn: &byzcoin.Spawn{
			ContractID: ContractKeyValueID,
			Args:       args,
		},
		SignerCounter: []uint64{1},
	})
	require.NoError(t, err)
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.NoError(t, err)

	myID := ctx.Instructions[0].DeriveID("")
	pr, err := cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()),
		2*genesisMsg.BlockInterval, nil)
	require.NoError(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	v, _, _, err := pr.Get(myID.Slice())
	require.NoError(t, err)
	kvStore := &KVStorage{}
	err = protobuf.Decode(v, kvStore)
	require.NoError(t, err)
	for _, kv := range kvStore.KV {
		fmt.Println(kv.Key, string(kv.Value))
	}

	_k, _v := pr.InclusionProof.KeyValue()
	fmt.Println(_k, _v)

	args = make(byzcoin.Arguments, 1)
	args[0] = byzcoin.Argument{Name: "key3", Value: []byte("haydo")}

	ctx, err = cl.CreateTransaction(byzcoin.Instruction{
		InstanceID: myID,
		Invoke: &byzcoin.Invoke{
			ContractID: ContractKeyValueID,
			Command:    "update",
			Args:       args,
		},
		SignerCounter: []uint64{2},
	})
	require.NoError(t, err)
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	_, err = cl.AddTransactionAndWait(ctx, 2)
	require.NoError(t, err)

	buf, err := protobuf.Encode(pr)
	require.NoError(t, err)
	fmt.Println("Size of proof:", len(buf))

	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()),
		2*genesisMsg.BlockInterval, nil)
	require.NoError(t, err)
	v, _, _, err = pr.Get(myID.Slice())
	require.NoError(t, err)

	kvStore = &KVStorage{}
	err = protobuf.Decode(v, kvStore)
	require.NoError(t, err)
	fmt.Println("====")
	for _, kv := range kvStore.KV {
		fmt.Println(kv.Key, string(kv.Value))
	}

	buf, err = protobuf.Encode(pr)
	require.NoError(t, err)
	fmt.Println("Size of proof:", len(buf))

	_k, _v = pr.InclusionProof.KeyValue()
	fmt.Println(_k, _v)
	fmt.Println(myID.Slice())
	//skCl := skipchain.NewClient()
	//sb, err := skCl.GetSingleBlock(roster, pr.Latest.SkipChainID())
	//require.NoError(t, err)
	//times := make([]time.Duration, 1000)
	//for i := 0; i < 1000; i++ {
	//	start := time.Now()
	//	err = pr.VerifyFromBlock(sb)
	//	require.NoError(t, err)
	//	times[i] = time.Since(start)
	//}
	//
	//sum := 0.0
	//for i := 0; i < 1000; i++ {
	//	sum += times[i].Seconds()
	//}
	//fmt.Println(sum / float64(1000))
}

type MyStruct struct {
	F1, F2, F3, F4, F5, F6, F7 string
	I1, I2, I3, I4, I5, I6, I7 int64
}

func BenchmarkAppendingStructs(b *testing.B) {
	var s []MyStruct

	for i := 0; i < b.N; i++ {
		s = append(s, MyStruct{})
	}
	for i := 0; i < b.N; i++ {
		foo(s, b.N)
	}
}

func BenchmarkAppendingPointers(b *testing.B) {
	var s []*MyStruct

	for i := 0; i < b.N; i++ {
		s = append(s, &MyStruct{})
	}
	for i := 0; i < b.N; i++ {
		foobar(s, b.N)
	}
}

func foo(s []MyStruct, cnt int) {
	for i := 0; i < cnt; i++ {
		_ = s[i].I3 + s[i].I4
		s[i].I7 = int64(i)
	}
}

func foobar(s []*MyStruct, cnt int) {
	for i := 0; i < cnt; i++ {
		_ = s[i].I3 + s[i].I4
		s[i].I7 = int64(i)
	}
}
