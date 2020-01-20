package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/dedis/protean/state"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/shuffle"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
	"go.dedis.ch/protobuf"
)

type InstanceID [32]byte

type IID struct {
	ID InstanceID
}

type Boo struct {
	B  []*IID
	Es []bool
}

type Goo struct {
	//Ctxs []byzcoin.ClientTransaction
	//Ctxs []*byzcoin.ClientTransaction
	Ps []*byzcoin.GetProofResponse
}

func main() {
	//rosterPtr := flag.String("r", "", "roster.toml file")
	//filePtr := flag.String("f", "", "json file")
	//flag.Parse()
	//roster, err := utils.ReadRoster(rosterPtr)
	//if err != nil {
	//fmt.Println(err)
	//os.Exit(1)
	//}
	//units, err := sys.PrepareUnits(roster, filePtr)
	//if err != nil {
	//fmt.Println(err)
	//os.Exit(1)
	//}
	//for _, u := range units {
	//fmt.Println(u.Type, u.Name, u.NumNodes, u.Txns)
	//}
	//testDarc()
	//testHash()
	//testEncode()
	//testState()
	//testPoint()
	//testEmbedLen()
	//testProtobuf()
	//testbyz()
	testIdentity()
	//testReencryption()
	//testencode()
	//testproof()
}

type Abbas struct {
	A []string
	//A []*IID
}

func testencode() {
	//var r [32]byte
	//temp := make([]byte, 32)
	//rand.Read(temp)
	//copy(r[:], temp[:32])
	l := make([]string, 10)
	//l := make([]*IID, 10)
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			//if i < 8 {
			l[i] = "haydar"
			//l[i] = &IID{ID: r}
		}
	}
	abbas := &Abbas{A: l}
	buf, err := protobuf.Encode(abbas)
	fmt.Println(err)
	dd := &Abbas{}
	protobuf.Decode(buf, dd)
	for i, ll := range dd.A {
		//fmt.Println(i, ll.ID)
		fmt.Println(i, ll)
	}
}

func testReencryption() {
	s := cothority.Suite
	x1 := s.Scalar().Pick(s.RandomStream())
	y1 := s.Point().Mul(x1, nil)

	mesg := []byte("abbas")
	k := s.Point().Embed(mesg, s.RandomStream())
	r := s.Scalar().Pick(s.RandomStream())
	b1 := s.Point().Mul(r, nil)
	a1 := s.Point().Add(s.Point().Mul(r, y1), k)
	fmt.Println("1:", k)

	//Decryption
	S := s.Point().Mul(x1, b1)
	pt := s.Point().Sub(a1, S)
	fmt.Println("2:", pt)

	neg := x1.Clone().Neg(x1)
	dd := s.Point().Mul(neg, b1)
	ptt := s.Point().Add(a1, dd)
	fmt.Println("3:", ptt)

	//id := s.Point().Null()
	//s_ := s.Point().Sub(id, S)
	//ptt := s.Point().Add(a1, s_)
	//fmt.Println(ptt)
	x2 := s.Scalar().Pick(s.RandomStream())
	y2 := s.Point().Mul(x2, nil)

	delta := s.Scalar().Pick(s.RandomStream())
	b2 := s.Point().Mul(delta, nil)
	id := s.Point().Null()
	S = s.Point().Mul(x1, b1)
	b1x1_inv := s.Point().Sub(id, S)
	y2_delta := s.Point().Mul(delta, y2)
	c_j := s.Point().Add(b1x1_inv, y2_delta)
	a2 := s.Point().Add(a1, c_j)

	//Decryption
	ss := s.Point().Mul(x2, b2)
	pt = s.Point().Sub(a2, ss)
	fmt.Println(pt)

	// mu1, mu2
	mu1_w1 := s.Point().Mul(x1, b1)
	mu2_w2 := s.Point().Mul(delta, y2)
	sigma := s.Point().Sub(mu1_w1, mu2_w2)
	fmt.Println("sigma:", sigma)
	//fmt.Println("sigma:", s.Point().Sub(a2, a1))
	fmt.Println("sigma:", s.Point().Sub(a1, a2))
}

func testIdentity() {
	p1 := cothority.Suite.Point().Pick(cothority.Suite.RandomStream())
	pn := cothority.Suite.Point().Null()
	fmt.Println(p1, pn)
	pp := cothority.Suite.Point().Add(p1, pn)
	fmt.Println(pp)

	fmt.Println("-------------------------")
	for i := 0; i < 5; i++ {
		fmt.Println(cothority.Suite.Point().Null())
	}
}

func testproof() {
	prs := make([]*byzcoin.GetProofResponse, 5)
	prs[3] = &byzcoin.GetProofResponse{
		Version: 4,
		Proof:   byzcoin.Proof{},
	}
	gg := &Goo{Ps: prs}
	buf, err := protobuf.Encode(gg)
	fmt.Println(err)
	fmt.Println(len(buf))
	fmt.Println(buf)
	dd := &Goo{}
	protobuf.Decode(buf, dd)
	for _, d := range dd.Ps {
		fmt.Println(d)
	}
}

//func testbyz() {
////ctxs := make([]byzcoin.ClientTransaction, 10)
//ctxs := make([]*byzcoin.ClientTransaction, 10)
//ctxs[3] = &byzcoin.ClientTransaction{
//Instructions: []byzcoin.Instruction{{
//InstanceID: byzcoin.NewInstanceID([]byte("abbas")),
//Spawn: &byzcoin.Spawn{
//ContractID: byzcoin.ContractNamingID,
//Args:       nil,
//},
//SignerCounter: []uint64{1},
//}},
//}
////ctxs[4] = byzcoin.ClientTransaction{
////Instructions: []byzcoin.Instruction{{
////InstanceID: byzcoin.NewInstanceID([]byte("kalmi")),
////Spawn: &byzcoin.Spawn{
////ContractID: byzcoin.ContractNamingID,
////Args:       nil,
////},
////SignerCounter: []uint64{2},
////}},
////}
//gg := &Goo{Ctxs: ctxs}
//buf, err := protobuf.Encode(gg)
//fmt.Println(err)
//fmt.Println(len(buf))
//fmt.Println(buf)
//dd := &Goo{}
//protobuf.Decode(buf, dd)
//for _, d := range dd.Ctxs {
//fmt.Println(d)
//}
//fmt.Println(len(dd.Ctxs))
//}

func testProtobuf() {
	var r [32]byte
	temp := make([]byte, 32)
	rand.Read(temp)
	copy(r[:], temp[:32])

	iids := make([]*IID, 10)
	es := make([]bool, 10)
	iids[0] = &IID{ID: r}
	es[0] = true
	iids[3] = &IID{ID: r}
	es[3] = true
	iids[5] = &IID{ID: r}
	es[5] = true
	iids[6] = &IID{ID: r}
	es[6] = true
	for i, ii := range iids {
		if ii == nil {
			es[i] = false
		}
	}

	bb := &Boo{B: iids, Es: es}
	dd, err := protobuf.Encode(bb)
	fmt.Println(err)
	fmt.Println("Byte count:", len(dd))
	fmt.Println(dd)
	ff := &Boo{}
	protobuf.Decode(dd, ff)

	//fmt.Println(len(ff.B))
	//for i, s := range ff.B {
	//fmt.Println(i, s.ID)
	//}
	newarr := make([]InstanceID, 10)
	idx := 0
	for i, valid := range ff.Es {
		//if id == nil {
		//fmt.Println("nil")
		//} else {
		//fmt.Println("not nil")
		//}
		if valid {
			newarr[i] = ff.B[idx].ID
			idx++
		}
	}
	for _, na := range newarr {
		fmt.Println(na)
	}
}

func testEmbedLen() {
	ptLen := cothority.Suite.Point().EmbedLen()
	fmt.Println(ptLen)
}

func testPoint() {
	rand := cothority.Suite.RandomStream()
	h := cothority.Suite.Scalar().Pick(rand)
	H := cothority.Suite.Point().Mul(h, nil)
	newstr := H.String()
	fmt.Println("This is the String() return:", newstr)
	fmt.Println(H)
	dd, err := encoding.PointToStringHex(cothority.Suite, H)
	fmt.Println(dd, err)
	bb := []byte(dd)
	fmt.Println(bb)
	ss := string(bb)
	fmt.Println(ss)
	pt, err := encoding.StringHexToPoint(cothority.Suite, ss)
	fmt.Println(pt, err)

}

func testState() {
	fmt.Println(state.UPD)
}

type Foo struct {
	F map[string]*[]kyber.Point
}

type KeyList []kyber.Point

func testEncode() {
	n := 5
	slc := make([]kyber.Point, n)
	rand := cothority.Suite.RandomStream()
	for i := 0; i < n; i++ {
		h := cothority.Suite.Scalar().Pick(rand)
		slc[i] = cothority.Suite.Point().Mul(h, nil)
	}
	fmt.Println(len(slc))
	for i := 0; i < n; i++ {
		fmt.Println(slc[i].String())
	}
	ff := make(map[string]*[]kyber.Point)
	ff["abbas"] = &slc
	foo := &Foo{F: ff}
	dd, err := protobuf.Encode(foo)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(dd)
}

type Anan struct {
	A map[string]int
}

func testHash() {
	mm := make(map[string]int)
	mm["abbas"] = 7
	mm["kamil"] = 8
	aa := &Anan{A: mm}
	for i := 0; i < 20; i++ {
		h := sha256.New()
		data, err := protobuf.Encode(aa)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		h.Write(data)
		dig := h.Sum(nil)
		fmt.Println(dig)
	}
}

func testDarc() {

	owner := darc.NewSignerEd25519(nil, nil)
	d := darc.NewDarc(darc.InitRules([]darc.Identity{owner.Identity()}, []darc.Identity{owner.Identity()}), []byte("owner"))
	user1 := darc.NewSignerEd25519(nil, nil)
	user2 := darc.NewSignerEd25519(nil, nil)
	user3 := darc.NewSignerEd25519(nil, nil)
	err := d.Rules.AddRule("exe", expression.InitOrExpr(user1.Identity().String(), user2.Identity().String()))
	if err != nil {
		fmt.Println("add rule failed:", err)
		os.Exit(1)
	}
	var r *darc.Request
	r, err = darc.InitAndSignRequest(d.GetID(), "exe", []byte("test"), user3)
	err = r.Verify(d)
	fmt.Println("darc verify:", err)
}

func testShuffle() {
	k := 5
	n := 10

	suite := edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))
	rand := suite.RandomStream()

	// Create a "server" private/public keypair
	h := suite.Scalar().Pick(rand)
	H := suite.Point().Mul(h, nil)

	//c := make([]kyber.Scalar, k)
	//C := make([]kyber.Point, k)
	C := make([][]byte, k)
	for i := 0; i < k; i++ {
		//c[i] = suite.Scalar().Pick(rand)
		//C[i] = suite.Point().Mul(c[i], nil)
		C[i] = []byte("Hello world!")
	}

	X := make([]kyber.Point, k)
	Y := make([]kyber.Point, k)
	for i := 0; i < k; i++ {
		//dd, err := C[i].Data()
		//if err != nil {
		//fmt.Println("cannot embed point")
		//}
		//egp := utils.ElGamalEncrypt(H, dd)
		egp := utils.ElGamalEncrypt(H, C[i])
		X[i] = egp.K
		Y[i] = egp.C
	}
	for i := 0; i < n; i++ {
		Xbar, Ybar, prover := shuffle.Shuffle(suite, nil, H, X, Y, rand)
		prf, err := proof.HashProve(suite, "PairShuffle", prover)
		if err != nil {
			panic("Shuffle proof failed: " + err.Error())
		}
		// Check it
		verifier := shuffle.Verifier(suite, nil, H, X, Y, Xbar, Ybar)
		err = proof.HashVerify(suite, "PairShuffle", verifier, prf)
		if err != nil {
			panic("Shuffle verify failed: " + err.Error())
		}
		if i == n-1 {
			for j, c := range C {
				egp := &utils.ElGamalPair{
					K: Xbar[j],
					C: Ybar[j],
				}
				pt := utils.ElGamalDecrypt(h, *egp)
				fmt.Println("Orig:", c)
				plain, err := pt.Data()
				if err != nil {
					fmt.Println("decryption error:", err)
				} else {
					fmt.Println("Plain:", plain)
				}

			}
		}
	}
}
