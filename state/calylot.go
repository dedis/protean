package state

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

const ContractCalyLotteryID = "calyLottery"

type contractCalyLottery struct {
	byzcoin.BasicContract
	CalyLotteryStorage
}

type SetupData struct {
	LTSID    byzcoin.InstanceID
	X        kyber.Point
	CalyDarc *darc.Darc
}

type CalyLotteryStorage struct {
	//Key: public key of the participant
	//TODO: Removed sig from value. was it necessary?
	//Value: proof + hash of ticket
	SetupData SetupData
	// Key: public key in hex format || Value: encoded WriteDataValue
	WriteData []KV
	ReadData  []KV
}

type WriteDataValue struct {
	// Index saves us from iterating over the array
	Index      int
	WrProof    *byzcoin.Proof
	Ct         []byte // Encrypted ticket
	KeyHash    []byte // Hash of the symmetric key
	TicketHash []byte //Hash of the ticket
}

type ReadDataValue struct {
	Index  int
	RProof *byzcoin.Proof
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
	keys := &Keys{}
	err = protobuf.Decode(klBytes, keys)
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
		wdv := &WriteDataValue{Index: i}
		valBuf, err = protobuf.Encode(wdv)
		if err != nil {
			log.Errorf("[SPAWN] Protobuf encode failed: %v", err)
			return
		}
		kv := KV{
			// Key is the hexstring of public key
			Key:     k,
			Value:   valBuf,
			Version: 0,
		}
		cls.WriteData = append(cls.WriteData, kv)
	}
	// Initialize ReadData
	cls.ReadData = make([]KV, len(keys.List))
	// Store LTSID
	copy(cls.SetupData.LTSID[:], ltsIDBytes)
	// Store Calypso public key
	pk, err := encoding.StringHexToPoint(cothority.Suite, string(pkBytes))
	cls.SetupData.X = pk
	// Store Calypso darc
	cls.SetupData.CalyDarc = darc
	// Encode state change
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
		wdv := &WriteDataValue{}
		err = protobuf.Decode(valBuf, wdv)
		if err != nil {
			log.Errorf("Protobuf decode failed: %v", err)
			return
		}
		// 1- Check the version number
		version := binary.LittleEndian.Uint32(verBuf)
		kvPair := cls.WriteData[wdv.Index]
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
		cls.WriteData[wdv.Index].Value = valBuf
		cls.WriteData[wdv.Index].Version = version
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
		lrBuf := inst.Invoke.Args.Search("data")
		if lrBuf == nil {
			log.Errorf("Missing logread data")
			return
		}
		verBuf := inst.Invoke.Args.Search("version")
		if verBuf == nil {
			log.Errorf("Missing version number")
			return
		}
		rdv := &ReadDataValue{}
		err = protobuf.Decode(lrBuf, rdv)
		if err != nil {
			log.Errorf("Protobuf decode failed: %v", err)
			return
		}
		// 1- Check the version number
		version := binary.LittleEndian.Uint32(verBuf)
		kvPair := cls.ReadData[rdv.Index]
		if (kvPair.Version + 1) != version {
			log.Errorf("New version number has to be %d, not %d", kvPair.Version+1, version)
			return
		}
		cls.ReadData[rdv.Index].Value = lrBuf
		cls.ReadData[rdv.Index].Version = version
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
		tBuf := inst.Invoke.Args.Search("ticket")
		if tBuf == nil {
			log.Errorf("Key:ticket has no value")
			return
		}
		//cls := &c.CalyLotteryStorage
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
