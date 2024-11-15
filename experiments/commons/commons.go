package commons

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/byzcoin"

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

const BATCH_COUNT int = 10
const UPDATE_WAIT int = 0
const PROOF_WAIT int = 20

func SetupStateUnit(roster *onet.Roster, blockTime int) (skipchain.SkipBlockID, error) {
	adminCl, byzID, err := libstate.SetupByzcoin(roster, blockTime)
	if err != nil {
		return nil, err
	}
	signer := darc.NewSignerEd25519(nil, nil)
	spawnDarc, err := adminCl.SpawnDarc(signer, adminCl.GMsg.GenesisDarc, 5)
	//spawnDarc, err := adminCl.SpawnDarc(signer, adminCl.GMsg.GenesisDarc, 1)
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

func SetupRegistry(regRoster *onet.Roster, dfile *string,
	keyMap map[string][]kyber.Point, blockTime int) (*execbase.ByzData,
	map[string]int, error) {
	threshMap := make(map[string]int)
	dfuReg, err := libclient.ReadDFUJSON(dfile)
	if err != nil {
		return nil, nil, err
	}
	for dfuName, keys := range keyMap {
		dfuReg.Units[dfuName].Keys = keys
		threshMap[dfuName] = dfuReg.Units[dfuName].Threshold
	}
	adminCl, _, err := registry.SetupByzcoin(regRoster, blockTime)
	if err != nil {
		return nil, nil, err
	}
	reply, err := adminCl.InitRegistry(dfuReg, 5)
	if err != nil {
		return nil, nil, err
	}
	pr, err := adminCl.Cl.WaitProof(reply.IID, time.Duration(blockTime)*time.Second, nil)
	if err != nil {
		return nil, nil, err
	}
	genesis, err := adminCl.Cl.FetchGenesisBlock(pr.Latest.SkipChainID())
	if err != nil {
		return nil, nil, err
	}
	return &execbase.ByzData{
		IID:     reply.IID,
		Proof:   pr,
		Genesis: genesis,
	}, threshMap, nil
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

func ReadSchedule(fpath string, numTxns int) ([]int, error) {
	readFile, err := os.Open(fpath)
	if err != nil {
		return nil, err
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	var fileLines []string
	for fileScanner.Scan() {
		fileLines = append(fileLines, fileScanner.Text())
	}
	err = readFile.Close()
	if err != nil {
		return nil, err
	}
	// Create dictionary
	baseMap := make(map[int][]int)
	for _, line := range fileLines {
		var values []int
		tokens := strings.Split(line, " ")
		key, err := strconv.Atoi(tokens[0])
		if err != nil {
			return nil, err
		}
		for i := 1; i < len(tokens); i++ {
			v, err := strconv.Atoi(tokens[i])
			if err != nil {
				return nil, err
			}
			values = append(values, v)
		}
		baseMap[key] = values
	}

	if numTxns < 20 {
		return baseMap[numTxns], nil
	} else {
		baseSchedule := baseMap[numTxns]
		lenBs := len(baseSchedule)
		factor := numTxns / 10
		schedule := make([]int, factor*lenBs)
		for i := 0; i < factor; i++ {
			begin := lenBs * i
			end := begin + lenBs
			copy(schedule[begin:end], baseSchedule[:])
		}
		return schedule, nil
	}
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

func PrepareStateProof(numInputs int, pr *byzcoin.Proof,
	genesis *skipchain.SkipBlock) map[string]*core.StateProof {
	sp := make(map[string]*core.StateProof)
	for i := 0; i < numInputs; i++ {
		key := fmt.Sprintf("data%d", i)
		sp[key] = &core.StateProof{
			Proof:   pr,
			Genesis: genesis,
		}
	}
	return sp
}

func StringToIntSlice(src string) []int {
	var dstSlice []int
	srcSlice := strings.Split(src, ";")
	for _, x := range srcSlice {
		xx, _ := strconv.Atoi(x)
		dstSlice = append(dstSlice, xx)
	}
	return dstSlice
}

func HashKeys(ps []kyber.Point) []byte {
	s := sha256.New()
	for _, p := range ps {
		data, _ := p.MarshalBinary()
		s.Write(data)
	}
	return s.Sum(nil)
}
