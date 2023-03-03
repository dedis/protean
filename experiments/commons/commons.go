package commons

import (
	"crypto/rand"
	"time"

	"github.com/dedis/protean/libclient"
	execbase "github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/libstate"
	"github.com/dedis/protean/registry"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

func SetupStateUnit(roster *onet.Roster, blockTime int) (skipchain.SkipBlockID, error) {
	adminCl, byzID, err := libstate.SetupByzcoin(roster, blockTime)
	if err != nil {
		return nil, err
	}
	signer := darc.NewSignerEd25519(nil, nil)
	spawnDarc, err := adminCl.SpawnDarc(signer, adminCl.GMsg.GenesisDarc, 5)
	if err != nil {
		return nil, err
	}
	req := &libstate.InitUnitRequest{
		ByzID:  byzID,
		Roster: roster,
		Darc:   spawnDarc,
		Signer: signer,
	}
	_, err = adminCl.Cl.InitUnit(req)
	if err != nil {
		return nil, err
	}
	err = adminCl.Cl.Close()
	if err != nil {
		return nil, err
	}
	return byzID, nil
}

func SetupRegistry(regRoster *onet.Roster, dfile *string, keyMap map[string][]kyber.Point) (*execbase.ByzData, error) {
	dfuReg, err := libclient.ReadDFUJSON(dfile)
	if err != nil {
		return nil, err
	}
	for dfuName, keys := range keyMap {
		dfuReg.Units[dfuName].Keys = keys
	}
	adminCl, _, err := registry.SetupByzcoin(regRoster, 5)
	if err != nil {
		return nil, err
	}
	reply, err := adminCl.InitRegistry(dfuReg, 5)
	if err != nil {
		return nil, err
	}
	pr, err := adminCl.Cl.WaitProof(reply.IID, 10*time.Second, nil)
	if err != nil {
		return nil, err
	}
	genesis, err := adminCl.Cl.FetchGenesisBlock(pr.Latest.SkipChainID())
	if err != nil {
		return nil, err
	}
	return &execbase.ByzData{
		IID:     reply.IID,
		Proof:   pr,
		Genesis: genesis,
	}, nil
}

func GenerateTicket(X kyber.Point) utils.ElGamalPair {
	randBytes := make([]byte, 24)
	rand.Read(randBytes)
	return utils.ElGamalEncrypt(X, randBytes)
}

func GenerateWriters(count int) []darc.Signer {
	writers := make([]darc.Signer, count)
	for i := 0; i < count; i++ {
		writers[i] = darc.NewSignerEd25519(nil, nil)
	}
	return writers
}
