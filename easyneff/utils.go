package easyneff

import (
	"time"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
)

func GenerateInitRequest(roster *onet.Roster) *InitUnitRequest {
	//scData := &protean.ScInitData{
	scData := &sys.ScInitData{
		MHeight: 2,
		BHeight: 2,
	}
	//uData := &protean.BaseStorage{
	uData := &sys.BaseStorage{
		//UInfo: &protean.UnitInfo{
		UInfo: &sys.UnitInfo{
			UnitID:   "shuffle",
			UnitName: "shuffleUnit",
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

func TestRequest(n int, msg []byte) (ShuffleRequest, kyber.Scalar, kyber.Point) {
	r := random.New()
	pairs := make([]utils.ElGamalPair, n)
	secret := cothority.Suite.Scalar().Pick(r)
	public := cothority.Suite.Point().Mul(secret, nil)
	for i := range pairs {
		c := utils.ElGamalEncrypt(public, msg)
		pairs[i] = utils.ElGamalPair{K: c.K, C: c.C}
	}

	return ShuffleRequest{
		Pairs: pairs,
		G:     cothority.Suite.Point().Base(),
		H:     cothority.Suite.Point().Pick(r),
	}, secret, public
}

func GenerateRequest(n int, msg []byte, key kyber.Point) ShuffleRequest {
	var public kyber.Point
	r := random.New()
	//pairs := make([]ElGamalPair, n)
	pairs := make([]utils.ElGamalPair, n)
	for i := range pairs {
		if key != nil {
			public = key
		} else {
			secret := cothority.Suite.Scalar().Pick(r)
			public = cothority.Suite.Point().Mul(secret, nil)
		}
		c := utils.ElGamalEncrypt(public, msg)
		//pairs[i] = ElGamalPair{C1: c.K, C2: c.C}
		pairs[i] = utils.ElGamalPair{K: c.K, C: c.C}
	}

	return ShuffleRequest{
		Pairs: pairs,
		G:     cothority.Suite.Point().Base(),
		H:     cothority.Suite.Point().Pick(r),
	}
}

func GetServiceID() onet.ServiceID {
	return serviceID
}