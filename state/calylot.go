package state

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

const ContractCalyLotteryID = "calyLottery"

type DummyKeys struct {
	List []kyber.Point
}

// Used for communication between the client-side and Calylot contract
type StructProofData struct {
	Ps []*byzcoin.Proof
}

type StructRevealData struct {
	Rs []LotteryRevealData
}

type contractCalyLottery struct {
	byzcoin.BasicContract
	CalyLotteryStorage
}

type CalyLotteryStorage struct {
	SetupData SetupData
	Valid     []byte
	// Key: public key in hex format || Value: encoded LotteryJoinDataValue
	LotteryJoinData []KV
	RProofs         []*byzcoin.Proof
	RevealData      []LotteryRevealData
}

type SetupData struct {
	LTSID     byzcoin.InstanceID
	X         kyber.Point
	CalyDarc  *darc.Darc
	DummyKeys []kyber.Point
}

type LotteryJoinDataValue struct {
	// Index saves us from iterating over the array
	Index      int
	WrProof    *byzcoin.Proof
	Ct         []byte // Encrypted ticket
	KeyHash    []byte // Hash of the symmetric key
	TicketHash []byte //Hash of the ticket
}

type LotteryRevealData struct {
	DKID      string
	C         kyber.Point
	XhatEnc   kyber.Point
	Signature protocol.BlsSignature
}

func contractCalyLotteryFromBytes(in []byte) (byzcoin.Contract, error) {
	cv := &contractCalyLottery{}
	err := protobuf.Decode(in, &cv.CalyLotteryStorage)
	if err != nil {
		log.Errorf("Protobuf decode failed: %v", err)
		return nil, err
	}
	return cv, nil
}

func (c *contractCalyLottery) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		log.Errorf("GetValues failed: %v", err)
		return
	}
	cls := &c.CalyLotteryStorage
	ltsIDBytes := inst.Spawn.Args.Search("ltsid")
	if ltsIDBytes == nil {
		log.Errorf("Missing ltsid")
		return
	}
	pkBytes := inst.Spawn.Args.Search("sharedpk")
	if pkBytes == nil {
		log.Errorf("Missing shared public key")
		return
	}
	klBytes := inst.Spawn.Args.Search("keylist")
	if klBytes == nil {
		log.Errorf("Missing key list")
		return
	}
	darcBytes := inst.Spawn.Args.Search("calydarc")
	if darcBytes == nil {
		log.Errorf("Missing darc")
		return
	}
	dummyBytes := inst.Spawn.Args.Search("dummy")
	if dummyBytes == nil {
		log.Errorf("Missing dummy service keys")
		return
	}
	keys := &Keys{}
	err = protobuf.Decode(klBytes, keys)
	if err != nil {
		log.Errorf("Protobuf decode failed: %v", err)
		return
	}
	dummyKeys := &DummyKeys{}
	err = protobuf.Decode(dummyBytes, dummyKeys)
	if err != nil {
		log.Errorf("Protobuf decode failed: %v", err)
		return
	}
	darc := &darc.Darc{}
	err = protobuf.Decode(darcBytes, darc)
	if err != nil {
		log.Errorf("Protobuf decode failed: %v", err)
		return
	}
	// Create a KV entry for all the eligible lottery participants
	for i, k := range keys.List {
		var valBuf []byte
		value := &LotteryJoinDataValue{Index: i}
		valBuf, err = protobuf.Encode(value)
		if err != nil {
			log.Errorf("Protobuf encode failed: %v", err)
			return
		}
		kv := KV{
			// Key is the hexstring of public key
			Key:     k,
			Value:   valBuf,
			Version: 0,
		}
		cls.LotteryJoinData = append(cls.LotteryJoinData, kv)
	}
	// Store LTSID
	copy(cls.SetupData.LTSID[:], ltsIDBytes)
	// Store Calypso public key
	pk, err := encoding.StringHexToPoint(cothority.Suite, string(pkBytes))
	cls.SetupData.X = pk
	// Store Calypso darc
	cls.SetupData.CalyDarc = darc
	// Store DummyService keys
	cls.SetupData.DummyKeys = dummyKeys.List
	// Encode state change
	cls.Valid = make([]byte, len(keys.List))
	clsBuf, err := protobuf.Encode(&c.CalyLotteryStorage)
	if err != nil {
		log.Errorf("Protobuf encode failed: %v", err)
		return
	}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Create, inst.DeriveID(""), ContractCalyLotteryID, clsBuf, darcID),
	}
	return
}

func (c *contractCalyLottery) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		log.Errorf("Get values failed: %v", err)
		return
	}
	cls := &c.CalyLotteryStorage
	switch inst.Invoke.Command {
	case "storejoin":
		valBuf := inst.Invoke.Args.Search("data")
		if valBuf == nil {
			log.Errorf("Missing store ticket data")
			return
		}
		sig := inst.Invoke.Args.Search("sig")
		if sig == nil {
			log.Errorf("Missing signature")
			return
		}
		verBuf := inst.Invoke.Args.Search("version")
		if verBuf == nil {
			log.Errorf("Missing version number")
			return
		}
		val := &LotteryJoinDataValue{}
		err = protobuf.Decode(valBuf, val)
		if err != nil {
			log.Errorf("Protobuf decode failed: %v", err)
			return
		}
		// 1- Check the version number
		version := binary.LittleEndian.Uint32(verBuf)
		kvPair := cls.LotteryJoinData[val.Index]
		pkStr := kvPair.Key
		if (kvPair.Version + 1) != version {
			log.Errorf("New version number has to be %d, not %d", kvPair.Version+1, version)
			return
		}
		// 2- Make sure that the client is updating the correct key
		err = c.authorizeAccess(pkStr, valBuf, verBuf, sig)
		if err != nil {
			log.Errorf("Not authorized to update the value for key %v: %v", pkStr, err)
			return
		}
		cls.LotteryJoinData[val.Index].Value = valBuf
		cls.LotteryJoinData[val.Index].Version = version
		cls.Valid[val.Index] = 1
		var clsBuf []byte
		clsBuf, err = protobuf.Encode(&c.CalyLotteryStorage)
		if err != nil {
			log.Errorf("Protobuf encode failed: %v", err)
			return
		}
		sc = []byzcoin.StateChange{
			byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID, ContractCalyLotteryID, clsBuf, darcID),
		}
		return
	case "storeread":
		log.LLvl1("In storeread")
		valid := inst.Invoke.Args.Search("valid")
		if valid == nil {
			log.Errorf("Missing valid")
			return
		}
		pBuf := inst.Invoke.Args.Search("proofs")
		if pBuf == nil {
			log.Errorf("Missing storeread data")
			return
		}
		pd := &StructProofData{}
		err = protobuf.Decode(pBuf, pd)
		if err != nil {
			log.Errorf("Protobuf decode failed: %v", err)
			return
		}
		cls.Valid = valid
		cls.RProofs = pd.Ps
		var clsBuf []byte
		clsBuf, err = protobuf.Encode(&c.CalyLotteryStorage)
		if err != nil {
			log.Errorf("Protobuf encode failed: %v", err)
			return
		}
		sc = []byzcoin.StateChange{
			byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID, ContractCalyLotteryID, clsBuf, darcID),
		}
		return
	case "finalize":
		valid := inst.Invoke.Args.Search("valid")
		if valid == nil {
			log.Errorf("Missing valid")
			return
		}
		dataBuf := inst.Invoke.Args.Search("data")
		if dataBuf == nil {
			log.Errorf("Missing data")
			return
		}
		srd := &StructRevealData{}
		err = protobuf.Decode(dataBuf, srd)
		if err != nil {
			log.Errorf("Protobuf decode error: %v", err)
			return
		}
		log.Info("Before the loop")
		cls := &c.CalyLotteryStorage
		cls.RevealData = srd.Rs

		for i, rd := range cls.RevealData {
			ljd := &LotteryJoinDataValue{}
			err = verifySignature(rd.DKID, rd.XhatEnc, rd.Signature, cls.SetupData.DummyKeys)
			if err != nil {
				log.Errorf("Cannot verify signature for %s: %v", rd.DKID, err)
			} else {
				log.LLvl1("********* Signature verification successful **********")
			}
			err := protobuf.Decode(cls.LotteryJoinData[i].Value, ljd)
			if err != nil {
				log.Errorf("PROTOBUF ERROR: %v", err)
			}
			key, err := recoverKeyNT(rd.XhatEnc, rd.C)
			if err != nil {
				log.Errorf("CANNOT RECOVER KEY: %v", err)
			}
			s := sha256.New()
			//kb, err := rd.XhatEnc.MarshalBinary()
			//if err != nil {
			//log.Errorf("CANNOT MARSH BIN: %v", err)
			//}
			//s.Write(kb)
			s.Write(key)
			log.LLvlf1("================= %x %x ==============", ljd.KeyHash, s.Sum(nil))
		}
		//kvs := &KVStorage{}
		//err = protobuf.Decode(tBuf, kvs)
		//if err != nil {
		//log.Errorf("Protobuf decode error: %v", err)
		//return
		//}
		//cls.checkTickets(kvs)
		//cls.pickWinner()
		return
	default:
		return nil, nil, fmt.Errorf("Invalid invoke command")
	}
}

func (c *contractCalyLottery) authorizeAccess(pkStr string, valBuf []byte, verBuf []byte, sig []byte) error {
	pk, err := encoding.StringHexToPoint(cothority.Suite, pkStr)
	if err != nil {
		return fmt.Errorf("cannot convert string to point - %v", err)
	}
	h := sha256.New()
	//h.Write(data)
	h.Write(valBuf)
	h.Write(verBuf)
	err = schnorr.Verify(cothority.Suite, pk, h.Sum(nil), sig)
	if err != nil {
		return fmt.Errorf("cannot verify signature - %v", err)
	}
	return nil
}

func (ls *CalyLotteryStorage) pickWinner() string {
	return ""
}

//func (ls *CalyLotteryStorage) checkTickets(tickets *KVStorage) bool {
//for i, ticket := range tickets.KV {
//wdv := &WriteDataValue{}
//h := sha256.New()
//h.Write(ticket.Value)
//err := protobuf.Decode(ls.WriteData.KV[i].Value, wdv)
//if err != nil {
//log.Errorf("Protobuf decode failed: %v", err)
//return false
//}
//if bytes.Compare(h.Sum(nil), wdv.Digest) != 0 {
//log.Errorf("Ticket for key %s does not match", ls.WriteData.KV[i].Key)
//return false
//}
//}
//return true
//}

func (c *contractCalyLottery) Delete(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		log.Errorf("Get values failed: %v", err)
		return
	}
	sc = byzcoin.StateChanges{byzcoin.NewStateChange(byzcoin.Remove, inst.InstanceID, ContractCalyLotteryID, nil, darcID)}
	return
}

func recoverKeyNT(XhatEnc kyber.Point, C kyber.Point) (key []byte, err error) {
	XhatInv := XhatEnc.Clone().Neg(XhatEnc)
	XhatInv.Add(C, XhatInv)
	key, err = XhatInv.Data()
	return
}

func verifySignature(DKID string, XhatEnc kyber.Point, sig protocol.BlsSignature, publics []kyber.Point) error {
	bnsuite := pairing.NewSuiteBn256()
	ptBuf, err := XhatEnc.MarshalBinary()
	if err != nil {
		return err
	}
	sh := sha256.New()
	sh.Write([]byte(DKID))
	sh.Write(ptBuf)
	data := sh.Sum(nil)
	return sig.Verify(bnsuite, data, publics)
}
