package commons

import (
	"fmt"
	"math/rand"
	"strings"
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

func GenerateBallots(numCandidates int, count int) []string {
	ballots := make([]string, count)
	for i := 0; i < count; i++ {
		base := strings.Repeat("0", numCandidates)
		idx := rand.Intn(len(base))
		ballots[i] = base[:idx] + "1" + base[idx+1:]
	}
	return ballots
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

func GenerateSchedule(seed int, numTxns int, numSlots int) []int {
	rand.Seed(int64(seed))
	slots := make([]int, numSlots)
	for i := 0; i < numTxns; i++ {
		slot := rand.Intn(numSlots)
		slots[slot]++
	}
	return slots
}

func PrepareData(numData int, size int) map[string][]byte {
	data := make(map[string][]byte)
	for i := 0; i < numData; i++ {
		buf := make([]byte, size)
		sz, err := rand.Read(buf)
		if sz != size {
			panic(err)
		}
		name := fmt.Sprintf("data%d", i)
		data[name] = buf
	}
	return data
}
