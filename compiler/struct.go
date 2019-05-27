package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	bolt "go.etcd.io/bbolt"
	"strconv"
	"strings"
)

type void struct{}

type FunctionalUnit struct {
	UnitType   int
	UnitName   string
	Roster     *onet.Roster
	PublicKeys []kyber.Point
	NumNodes   int
	NumFaulty  int
	Txns       []string
	//Txns       []*Transaction
}

type WfNode struct {
	Index int
	UId   string
	TId   string
	Deps  []int
}

type UnitData struct {
	UnitId   string
	UnitName string
	Txns     map[string]string
}

type CreateSkipchainRequest struct {
	Roster  *onet.Roster
	MHeight int
	BHeight int
}

type CreateSkipchainReply struct {
	Genesis []byte
	Sb      *skipchain.SkipBlock
}

type CreateUnitsRequest struct {
	Genesis []byte
	Units   []*FunctionalUnit
}

type CreateUnitsReply struct {
	Data []*UnitData
	//SbID skipchain.SkipBlockID
}

type ExecPlanRequest struct {
	Genesis  []byte
	Workflow []*WfNode
}

type ExecPlanReply struct {
	Signature []byte
}

type LogSkipchainRequest struct {
	Genesis []byte
}

type LogSkipchainReply struct {
}

func (req ExecPlanRequest) Hash() []byte {
	h := sha256.New()
	for _, wfn := range req.Workflow {
		h.Write([]byte(wfn.UId))
		h.Write([]byte(wfn.TId))
	}
	return h.Sum(nil)
}

func joinStrings(strs ...string) (string, error) {
	var sb strings.Builder
	for _, str := range strs {
		_, err := sb.WriteString(str)
		if err != nil {
			return "", err
		}
	}
	return sb.String(), nil
}

//func generateUnitKey(fu *FunctionalUnit) (string, error) {
func generateUnitId(fu *FunctionalUnit) (string, error) {
	var uid string
	typeStr := strconv.Itoa(fu.UnitType)
	uuidStr := fu.Roster.ID.String()
	log.Info("UUID STR IS:", uuidStr)
	uidStr, err := joinStrings(typeStr, fu.UnitName, uuidStr)
	if err != nil {
		log.Errorf("generateUnitKey error: %v", err)
		return uid, err
	}
	tmp := sha256.Sum256([]byte(uidStr))
	return hex.EncodeToString(tmp[:]), nil
}

func generateTxnIds(tList []string) map[string]string {
	txns := make(map[string]string)
	for _, txnName := range tList {
		tmp := sha256.Sum256([]byte(txnName))
		txns[hex.EncodeToString(tmp[:])] = txnName
	}
	return txns
}

func checkUnitKeys(db *bolt.DB, bucketName []byte, unitIDs ...string) error {
	err := db.View(func(tx *bolt.Tx) error {
		for _, id := range unitIDs {
			log.LLvl3("Hex key is", id)
			key, err := hex.DecodeString(id)
			if err != nil {
				log.Errorf("checkUnitKeys error:%v", err)
				return err
			}
			log.LLvl3("Checking key(byte):", key)
			val := tx.Bucket(bucketName).Get(key)
			if val == nil {
				return errors.New("Unit key does not exist")
			}
		}
		return nil
	})
	return err
}
