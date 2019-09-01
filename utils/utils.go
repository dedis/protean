package utils

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sort"

	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

var ps = pairing.NewSuiteBn256()

type ElGamalPair struct {
	K kyber.Point // C1
	C kyber.Point // C2
}

// ElGamalEncrypt performs the ElGamal encryption algorithm.
func ElGamalEncrypt(public kyber.Point, message []byte) ElGamalPair {
	if len(message) > cothority.Suite.Point().EmbedLen() {
		panic("message size is too long")
	}
	M := cothority.Suite.Point().Embed(message, random.New())

	// ElGamal-encrypt the point to produce ciphertext (K,C).
	egp := ElGamalPair{}
	k := cothority.Suite.Scalar().Pick(random.New()) // ephemeral private key
	egp.K = cothority.Suite.Point().Mul(k, nil)      // ephemeral DH public key
	S := cothority.Suite.Point().Mul(k, public)      // ephemeral DH shared secret
	egp.C = S.Add(S, M)                              // message blinded with secret
	return egp
}

// ElGamalDecrypt performs the ElGamal decryption algorithm.
func ElGamalDecrypt(private kyber.Scalar, egp ElGamalPair) kyber.Point {
	S := cothority.Suite.Point().Mul(private, egp.K) // regenerate shared secret
	return cothority.Suite.Point().Sub(egp.C, S)     // use to un-blind the message
}

func BlsCosiSign(s *blscosi.Service, r *onet.Roster, data []byte) (network.Message, error) {
	h := sha256.New()
	h.Write(data)
	resp, err := s.SignatureRequest(&blscosi.SignatureRequest{
		Message: h.Sum(nil),
		Roster:  r,
	})
	return resp, err
}

func VerifyBLSSignature(s interface{}, sig protocol.BlsSignature, publics []kyber.Point) error {
	data, err := protobuf.Encode(s)
	if err != nil {
		return err
	}
	h := sha256.New()
	h.Write(data)
	return sig.Verify(ps, h.Sum(nil), publics)
}

func ComputeWFHash(wf *sys.Workflow) ([]byte, error) {
	authBytes := SerializeAuthKeys(wf.AuthPublics)
	serialWf := &sys.SerializedWf{
		Nodes:       wf.Nodes,
		AuthPublics: authBytes,
		All:         wf.All,
	}
	buf, err := protobuf.Encode(serialWf)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(buf)
	return h.Sum(nil), err
}

func ComputeEPHash(ep *sys.ExecutionPlan) ([]byte, error) {
	authBytes := SerializeAuthKeys(ep.Workflow.AuthPublics)
	pubBytes := SerializeUnitKeys(ep.Publics)
	serialEp := &sys.SerializedEp{
		Swf: &sys.SerializedWf{
			Nodes:       ep.Workflow.Nodes,
			AuthPublics: authBytes,
			All:         ep.Workflow.All,
		},
		Publics: pubBytes,
	}
	buf, err := protobuf.Encode(serialEp)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(buf)
	return h.Sum(nil), nil
}

func SerializeUnitKeys(keyMap map[string]*sys.UnitIdentity) []byte {
	sz := len(keyMap)
	sortedKeys := make([]string, sz)
	idx := 0
	for k, _ := range keyMap {
		sortedKeys[idx] = k
		idx++
	}
	sort.Strings(sortedKeys)
	h := sha256.New()
	for i := 0; i < sz; i++ {
		key := sortedKeys[i]
		unitKeys := keyMap[key].Keys
		h.Write([]byte(key))
		for i := 0; i < len(unitKeys); i++ {
			h.Write([]byte(unitKeys[i].String()))
		}
	}
	return h.Sum(nil)
}

func SerializeAuthKeys(keyMap map[string]kyber.Point) []byte {
	sortedKeys := make([]string, len(keyMap))
	idx := 0
	for k, _ := range keyMap {
		sortedKeys[idx] = k
		idx++
	}
	sort.Strings(sortedKeys)
	h := sha256.New()
	for _, key := range sortedKeys {
		authKey := keyMap[key]
		h.Write([]byte(key))
		h.Write([]byte(authKey.String()))
	}
	return h.Sum(nil)
}

func StoreBlock(s *skipchain.Service, genesis skipchain.SkipBlockID, data []byte) error {
	db := s.GetDB()
	latest, err := db.GetLatest(db.GetByID(genesis))
	if err != nil {
		return err
	}
	block := latest.Copy()
	block.Data = data
	block.GenesisID = block.SkipChainID()
	block.Index++
	_, err = s.StoreSkipBlock(&skipchain.StoreSkipBlock{
		NewBlock:          block,
		TargetSkipChainID: latest.SkipChainID(),
	})
	return err
}

func CreateGenesisBlock(s *skipchain.Service, scCfg *sys.ScConfig, roster *onet.Roster) (*skipchain.StoreSkipBlockReply, error) {
	genesis := skipchain.NewSkipBlock()
	genesis.Roster = roster
	genesis.MaximumHeight = scCfg.MHeight
	genesis.BaseHeight = scCfg.BHeight
	genesis.VerifierIDs = skipchain.VerificationStandard
	reply, err := s.StoreSkipBlock(&skipchain.StoreSkipBlock{
		NewBlock: genesis,
	})
	return reply, err
}

func ReadRoster(path *string) (*onet.Roster, error) {
	file, err := os.Open(*path)
	if err != nil {
		log.Errorf("ReadRoster error: %v", err)
		return nil, err
	}

	group, err := app.ReadGroupDescToml(file)
	if err != nil {
		log.Errorf("ReadRoster error: %v", err)
		return nil, err
	}

	if len(group.Roster.List) == 0 {
		fmt.Println("Empty roster")
		log.Errorf("ReadRoster error: %v", err)
		return nil, err
	}
	return group.Roster, nil
}

//func GetServerKey(fname *string) (kyber.Point, error) {
//var keys []kyber.Point
//fh, err := os.Open(*fname)
//defer fh.Close()
//if err != nil {
//log.Errorf("GetServerKey error: %v", err)
//return nil, err
//}

//fs := bufio.NewScanner(fh)
//for fs.Scan() {
//tmp, err := encoding.StringHexToPoint(cothority.Suite, fs.Text())
//if err != nil {
//log.Errorf("GetServerKey error: %v", err)
//return nil, err
//}
//keys = append(keys, tmp)
//}
//return keys[0], nil
//}
