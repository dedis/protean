package libclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libstate"
	"github.com/dedis/protean/registry"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

var baseFile string
var contractFile string
var fsmFile string
var dfuFile string

var testSuite = pairing.NewSuiteBn256()

func init() {
	flag.StringVar(&baseFile, "base", "", "JSON file")
	flag.StringVar(&contractFile, "contract", "", "JSON file")
	flag.StringVar(&fsmFile, "fsm", "", "JSON file")
	flag.StringVar(&dfuFile, "dfu", "", "JSON file")
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func Test_InitContract(t *testing.T) {
	l := onet.NewTCPTest(cothority.Suite)
	_, roster, _ := l.GenTree(4, true)
	defer l.CloseAll()

	contract, err := ReadContractJSON(&baseFile)
	require.NoError(t, err)

	fsm, err := ReadFSMJSON(&fsmFile)
	require.NoError(t, err)

	adminCl, byzID, err := libstate.SetupByzcoin(roster, 1)
	require.NoError(t, err)

	req := &libstate.InitUnitRequest{
		ByzID:  byzID,
		Roster: roster,
	}
	_, err = adminCl.Cl.InitUnit(req)
	require.NoError(t, err)

	hdr := &core.ContractHeader{
		Contract:  contract,
		FSM:       fsm,
		CodeHash:  []byte("codehash"),
		Lock:      nil,
		CurrState: fsm.InitialState,
	}

	reply, err := adminCl.Cl.InitContract(hdr, adminCl.GMsg.GenesisDarc, 10)
	require.NoError(t, err)

	signer := darc.NewSignerEd25519(nil, nil)
	bc := byzcoin.NewClient(byzID, *roster)
	cl := libstate.NewClient(bc, signer)
	resp, err := cl.GetState(reply.CID)
	require.NoError(t, err)
	require.NotNil(t, resp)

	//buf, err := protobuf.Encode(&resp.Proof)
	//require.NoError(t, err)
	//h := testSuite.Hash()
	//h.Write(buf)
	//publics := roster.ServicePublics(libstate.ServiceName)
	//require.NoError(t, resp.Signature.VerifyWithPolicy(testSuite, buf, publics,
	//	sign.NewThresholdPolicy(3)))
}

func Test_StoreDependencyValue(t *testing.T) {
	contract, err := ReadContractJSON(&baseFile)
	require.NoError(t, err)
	value := base64.StdEncoding.EncodeToString([]byte("get_shuffle_rs"))
	err = StoreDependencyValue(contract, "reveal", "shuffle", "fnc_name", 0,
		value, contractFile)
	require.NoError(t, err)
	value = base64.StdEncoding.EncodeToString([]byte("prepare_shuffle"))
	err = StoreDependencyValue(contract, "reveal", "shuffle",
		"fnc_name", 2, value, contractFile)
	require.NoError(t, err)
	value = base64.StdEncoding.EncodeToString([]byte("get_shuffle_ws"))
	err = StoreDependencyValue(contract, "reveal", "shuffle", "fnc_name", 4,
		value, contractFile)
	require.NoError(t, err)
}

func Test_ReadContractJson(t *testing.T) {
	contract, err := ReadContractJSON(&contractFile)
	require.NoError(t, err)
	fmt.Println(contract.Workflows["vote"].Txns["cast_vote"])
	fmt.Println(contract.Workflows["vote"].Txns["cast_vote"].Opcodes[0].Dependencies == nil)
}

func Test_ReadFSMJson(t *testing.T) {
	fsm, err := ReadFSMJSON(&fsmFile)
	require.NoError(t, err)
	fmt.Println(fsm.InitialState, fsm.States)
}

func Test_ReadDFUJson(t *testing.T) {
	l := onet.NewTCPTest(cothority.Suite)
	_, roster, _ := l.GenTree(3, true)
	defer l.CloseAll()

	dfuReg, err := ReadDFUJSON(&dfuFile)
	require.NoError(t, err)

	for k := range dfuReg.Units {
		require.Nil(t, dfuReg.Units[k].Keys)
		dfuReg.Units[k].Keys = roster.Publics()
	}

	for _, v := range dfuReg.Units {
		require.NotNil(t, v.Keys)
	}

	adminCl, byzID, err := registry.SetupByzcoin(roster, 1)
	require.NoError(t, err)
	reply, err := adminCl.InitRegistry(dfuReg, 3)
	require.NoError(t, err)
	pr, err := adminCl.Cl.WaitProof(reply.IID, 2*time.Second, nil)
	require.NoError(t, err)
	v, _, _, err := pr.Get(reply.IID.Slice())
	kvStore := &core.Storage{}
	err = protobuf.Decode(v, kvStore)
	require.NoError(t, err)
	for _, kv := range kvStore.Store {
		if kv.Key == "registry" {
			reg := &core.DFURegistry{}
			err = protobuf.Decode(kv.Value, reg)
			require.NoError(t, err)
			for name, data := range reg.Units {
				fmt.Println(name, data)
			}
		}
	}

	bc := byzcoin.NewClient(byzID, *roster)
	cl := registry.NewClient(bc)
	pr2, err := cl.WaitProof(reply.IID, 1*time.Second, nil)
	require.NoError(t, err)
	v, _, _, err = pr2.Get(reply.IID.Slice())

	kvStore = &core.Storage{}
	err = protobuf.Decode(v, kvStore)
	require.NoError(t, err)
	for _, kv := range kvStore.Store {
		if kv.Key == "registry" {
			reg := &core.DFURegistry{}
			err = protobuf.Decode(kv.Value, reg)
			require.NoError(t, err)
			for name, data := range reg.Units {
				fmt.Println(name, data)
			}
		}
	}
}

func nchars(b byte, n int) string {
	s := make([]byte, n)
	for i := 0; i < n; i++ {
		s[i] = b
	}
	return string(s)
}

type Foo struct {
	Data []core.KV
}

func BenchmarkPBHashing(b *testing.B) {
	kvs := make([]core.KV, 100)
	for i := 0; i < 100; i++ {
		kvs[i].Key = nchars(byte(124), 32)
		kvs[i].Value = bytes.Repeat([]byte("1"), 1024)
	}

	foo := Foo{Data: kvs}
	for n := 0; n < b.N; n++ {
		h := sha256.New()
		buf, _ := protobuf.Encode(&foo)
		h.Write(buf)
		h.Sum(nil)
	}
}

func (f *Foo) Hash() {
	h := sha256.New()
	for _, kv := range f.Data {
		h.Write([]byte(kv.Key))
		h.Write(kv.Value)
	}
	h.Sum(nil)
}

func BenchmarkHashing(b *testing.B) {
	kvs := make([]core.KV, 100)
	for i := 0; i < 100; i++ {
		kvs[i].Key = nchars(byte(124), 32)
		kvs[i].Value = bytes.Repeat([]byte("1"), 1024)
	}

	foo := Foo{Data: kvs}
	for n := 0; n < b.N; n++ {
		foo.Hash()
	}
}

type FooMap struct {
	Data map[string][]byte
}

func (f *FooMap) Hash() []byte {
	sorted := make([]string, len(f.Data))
	i := 0
	for k := range f.Data {
		sorted[i] = k
		i++
	}
	sort.Strings(sorted)
	h := sha256.New()
	for _, k := range sorted {
		h.Write([]byte(k))
		h.Write(f.Data[k])
	}
	return h.Sum(nil)
}

func BenchmarkMapPBHashing(b *testing.B) {
	kvs := make(map[string][]byte)
	for i := 0; i < 1000; i++ {
		kvs[nchars(byte(i), 32)] = bytes.Repeat([]byte("1"), 1024)
	}

	foo := FooMap{Data: kvs}
	for n := 0; n < b.N; n++ {
		h := sha256.New()
		buf, _ := protobuf.Encode(&foo)
		h.Write(buf)
		h.Sum(nil)
	}
}

func BenchmarkMapHashing(b *testing.B) {
	kvs := make(map[string][]byte)
	for i := 0; i < 1000; i++ {
		kvs[nchars(byte(i), 32)] = bytes.Repeat([]byte("1"), 1024)
	}

	foo := FooMap{Data: kvs}
	for n := 0; n < b.N; n++ {
		foo.Hash()
	}
}

type Doo struct {
	Data map[string][]byte
}

func (d *Doo) Hash() []byte {
	keys := make([]string, len(d.Data))
	i := 0
	for k := range d.Data {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write(d.Data[k])
	}
	return h.Sum(nil)
}

func Test_DooHash(t *testing.T) {
	results := make([][]byte, 1000)
	for j := 0; j < 1000; j++ {
		data := make(map[string][]byte)
		for i := 0; i < 1000; i++ {
			data[fmt.Sprintf("%d", rand.Int())] = bytes.Repeat([]byte("a"), 100)
		}
		doo := Doo{Data: data}
		results[j] = doo.Hash()
	}
	for j := 0; j < 999; j++ {
		require.True(t, bytes.Equal(results[j], results[j+1]))
	}
}

type Goo struct {
	Data []int
}

func Test_GooProto(t *testing.T) {
	results := make([][]byte, 10)
	for j := 0; j < 10; j++ {
		data := make([]int, 100)
		for i := 0; i < 100; i++ {
			data[i] = i
			//data[fmt.Sprintf("%d", rand.Int())] = bytes.Repeat([]byte("a"), 100)
			//data[fmt.Sprintf("%d", i)] = bytes.Repeat([]byte("a"), 100)
		}
		doo := Goo{Data: data}
		buf, err := protobuf.Encode(&doo)
		require.NoError(t, err)
		results[j] = buf
	}
	for j := 0; j < 9; j++ {
		require.True(t, bytes.Equal(results[j], results[j+1]))
		var tmp Goo
		protobuf.Decode(results[j], &tmp)
		for i := 0; i < 100; i++ {
			require.True(t, i == tmp.Data[i])
		}
	}
}
