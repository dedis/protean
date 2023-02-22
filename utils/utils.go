package utils

import (
	"crypto/sha256"
	"encoding/binary"
	"golang.org/x/xerrors"
	"sort"
	"time"

	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3/network"

	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/protobuf"
)

var ps = pairing.NewSuiteBn256()

// Utility functions for ElGamalPair

type ElGamalPair struct {
	K kyber.Point // C1
	C kyber.Point // C2
}

type ElGamalPairs struct {
	Pairs []ElGamalPair
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

func (ps *ElGamalPairs) Hash() ([]byte, error) {
	h := sha256.New()
	for _, p := range ps.Pairs {
		bufK, err := p.K.MarshalBinary()
		if err != nil {
			return nil, err
		}
		bufC, err := p.C.MarshalBinary()
		if err != nil {
			return nil, err
		}
		h.Write(bufK)
		h.Write(bufC)
	}
	return h.Sum(nil), nil
}

func HashString(val string) []byte {
	h := sha256.New()
	h.Write([]byte(val))
	return h.Sum(nil)
}

func HashPoint(p kyber.Point) ([]byte, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(buf)
	return h.Sum(nil), nil
}

func HashPoints(ps []kyber.Point) ([]byte, error) {
	h := sha256.New()
	for _, ptext := range ps {
		data, err := ptext.MarshalBinary()
		if err != nil {
			return nil, xerrors.Errorf("couldn't marshal point: %v", err)
		}
		h.Write(data)
	}
	return h.Sum(nil), nil
}

func HashUint64(val uint64) []byte {
	h := sha256.New()
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, val)
	h.Write(buf)
	return h.Sum(nil)
}

// Utility functions for BLS

func GetBLSKeyPair(id *network.ServerIdentity) *key.Pair {
	return &key.Pair{
		Public:  id.ServicePublic(blscosi.ServiceName),
		Private: id.ServicePrivate(blscosi.ServiceName),
	}
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

func SearchPublicKey(p *onet.TreeNodeInstance, servID *network.ServerIdentity) int {
	for idx, si := range p.Roster().List {
		if si.Equal(servID) {
			return idx
		}
	}
	return -1
}

func ComputeEPHash(ep *sys.ExecutionPlan) ([]byte, error) {
	//authBytes := serializeAuthKeys(ep.Workflow.AuthPublics)
	pubBytes := serializeUnitKeys(ep.UnitPublics)
	serialEp := &sys.SerializedEp{
		Swf: &sys.SerializedWf{
			Nodes: ep.Workflow.Nodes,
			//AuthPublics: authBytes,
			//All:         ep.Workflow.All,
		},
		UnitPublics: pubBytes,
	}
	buf, err := protobuf.Encode(serialEp)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(buf)
	return h.Sum(nil), nil
}

func serializeUnitKeys(keyMap map[string]*sys.UnitIdentity) []byte {
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

//func serializeAuthKeys(keyMap map[string]kyber.Point) []byte {
//sortedKeys := make([]string, len(keyMap))
//idx := 0
//for k, _ := range keyMap {
//sortedKeys[idx] = k
//idx++
//}
//sort.Strings(sortedKeys)
//h := sha256.New()
//for _, key := range sortedKeys {
//authKey := keyMap[key]
//h.Write([]byte(key))
//h.Write([]byte(authKey.String()))
//}
//return h.Sum(nil)
//}

func ReverseMap(m map[string]string) map[string]string {
	revMap := make(map[string]string)
	for k, v := range m {
		revMap[v] = k
	}
	return revMap
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

func GenerateUnitConfig(compKeys []kyber.Point, roster *onet.Roster, id string, name string, txns map[string]string, blkIntv time.Duration) *sys.UnitConfig {
	scCfg := &sys.ScConfig{
		MHeight: 2,
		BHeight: 2,
	}
	uData := &sys.BaseStorage{
		UnitID:      id,
		UnitName:    name,
		Txns:        txns,
		CompPublics: compKeys,
	}
	return &sys.UnitConfig{
		Roster:       roster,
		ScCfg:        scCfg,
		BaseStore:    uData,
		BlkInterval:  blkIntv,
		DurationType: time.Second,
	}
}
