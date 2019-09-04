package threshold

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func hexToBytes(str string) ([]byte, error) {
	return hex.DecodeString(str)
}

func recoverCommit(numNodes int, cs *utils.ElGamalPair, pubShares []*share.PubShare) kyber.Point {
	threshold := numNodes - (numNodes-1)/3
	rc, err := share.RecoverCommit(cothority.Suite, pubShares, threshold, numNodes)
	if err != nil {
		log.Errorf("Cannot recover message: %v", err)
		return nil
	}
	p := cothority.Suite.Point().Sub(cs.C, rc)
	return p
}

func VerifyDecProof(sh kyber.Point, ei kyber.Scalar, fi kyber.Scalar, u kyber.Point, pub kyber.Point) bool {
	// sh = ui // u = g^r // pub = h^i
	//Verify proofs
	ufi := cothority.Suite.Point().Mul(fi, u)
	uiei := cothority.Suite.Point().Mul(cothority.Suite.Scalar().Neg(ei), sh)
	uiHat := cothority.Suite.Point().Add(ufi, uiei)
	gfi := cothority.Suite.Point().Mul(fi, nil)
	hiei := cothority.Suite.Point().Mul(cothority.Suite.Scalar().Neg(ei), pub)
	hiHat := cothority.Suite.Point().Add(gfi, hiei)
	hash := sha256.New()
	sh.MarshalTo(hash)
	uiHat.MarshalTo(hash)
	hiHat.MarshalTo(hash)
	e := cothority.Suite.Scalar().SetBytes(hash.Sum(nil))
	return e.Equal(ei)
}

func GenerateInitRequest(roster *onet.Roster) *InitUnitRequest {
	scCfg := &sys.ScConfig{
		MHeight: 2,
		BHeight: 2,
	}
	uData := &sys.BaseStorage{
		UnitID:   "threshold",
		UnitName: "thresholdUnit",
		Txns:     map[string]string{"a": "b", "c": "d"},
	}
	return &InitUnitRequest{
		Cfg: &sys.UnitConfig{
			Roster:       roster,
			ScCfg:        scCfg,
			BaseStore:    uData,
			BlkInterval:  10,
			DurationType: time.Second,
		},
	}
}

func GenerateMesgs(count int, m string, key kyber.Point) ([][]byte, []*utils.ElGamalPair) {
	mesgs := make([][]byte, count)
	cs := make([]*utils.ElGamalPair, count)
	for i := 0; i < count; i++ {
		s := fmt.Sprintf("%s%s%d%s", m, " -- ", i, "!")
		mesgs[i] = []byte(s)
		c := utils.ElGamalEncrypt(key, mesgs[i])
		cs[i] = &c
	}
	return mesgs, cs
}

func GenerateRandBytes() []byte {
	slc := make([]byte, 32)
	random.Bytes(slc, random.New())
	return slc
}
