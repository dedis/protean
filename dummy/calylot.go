package dummy

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
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

func contractCalyLotteryFromBytes(in []byte) (byzcoin.Contract, error) {
	cv := &contractCalyLottery{}
	err := protobuf.Decode(in, &cv.CalyLotteryStorage)
	if err != nil {
		log.Errorf("Protobuf decode failed: %v", err)
		return nil, err
	}
	return cv, nil
}

//func (c *contractCalyLottery) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
//cout = coins
//var darcID darc.ID
//_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
//if err != nil {
//log.Errorf("GetValues failed: %v", err)
//return
//}
//ls := &c.CalyLotteryStorage
//lvStruct := &CalyLotteryValue{}
//for _, kv := range inst.Spawn.Args {
//err = protobuf.Decode(kv.Value, lvStruct)
//if err != nil {
//log.Errorf("Protobuf decode failed: %v", err)
//return
//}
//ok := authorizeAccess(kv.Name, lvStruct)
//if !ok {
//log.Errorf("Not authorized to insert a value for the key %s", kv.Name)
//return
//}
//ls.Storage = append(ls.Storage, KV{kv.Name, kv.Value})
//}
//lsBuf, err := protobuf.Encode(&c.CalyLotteryStorage)
//if err != nil {
//log.Errorf("Protobuf encode failed: %v", err)
//return
//}
//sc = []byzcoin.StateChange{
//byzcoin.NewStateChange(byzcoin.Create, inst.DeriveID(""), ContractCalyLotteryID, lsBuf, darcID),
//}
//return
//}

func (c *contractCalyLottery) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		log.Errorf("Get values failed: %v", err)
		return
	}
	switch inst.Invoke.Command {
	case "addwrite":
		var buf []byte
		kvd := &c.CalyLotteryStorage.WriteData
		kvd.Update(inst.Invoke.Args)
		buf, err = protobuf.Encode(kvd)
		if err != nil {
			log.Errorf("Protobuf encode failed: %v", err)
			return
		}
		sc = []byzcoin.StateChange{
			byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID, ContractCalyLotteryID, buf, darcID),
		}
		return
	case "addread":
		var rdBuf []byte
		data := inst.Invoke.Args.Search("data")
		if data == nil {
			log.Errorf("Key:data has no value")
			return
		}
		cls := &c.CalyLotteryStorage
		cls.ReadData = append(cls.ReadData, data)
		rdBuf, err = protobuf.Encode(cls.ReadData)
		if err != nil {
			log.Errorf("Protobuf encode failed: %v", err)
			return
		}
		sc = []byzcoin.StateChange{
			byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID, ContractCalyLotteryID, rdBuf, darcID),
		}
		return
	case "finalize":
		tBuf := inst.Invoke.Args.Search("ticket")
		if tBuf == nil {
			log.Errorf("Key:ticket has no value")
			return
		}
		cls := &c.CalyLotteryStorage
		kvs := &KVStorage{}
		err = protobuf.Decode(tBuf, kvs)
		if err != nil {
			log.Errorf("Protobuf decode error: %v", err)
			return
		}
		cls.checkTickets(kvs)
		cls.pickWinner()
		return
	default:
		return nil, nil, fmt.Errorf("Invalid invoke command")
	}
}

func (ls *CalyLotteryStorage) pickWinner() string {

	return ""
}

func (ls *CalyLotteryStorage) checkTickets(tickets *KVStorage) bool {
	for i, ticket := range tickets.KV {
		wdv := &WriteDataValue{}
		h := sha256.New()
		h.Write(ticket.Value)
		err := protobuf.Decode(ls.WriteData.KV[i].Value, wdv)
		if err != nil {
			log.Errorf("Protobuf decode failed: %v", err)
			return false
		}
		if bytes.Compare(h.Sum(nil), wdv.Digest) != 0 {
			log.Errorf("Ticket for key %s does not match", ls.WriteData.KV[i].Key)
			return false
		}
	}
	return true
}

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

func (ls *CalyLotteryStorage) Update(args byzcoin.Arguments) {
	lvStruct := &CalyLotteryValue{}
	for _, kv := range args {
		updated := false
		for i, stored := range ls.WriteData.KV {
			if stored.Key == kv.Name {
				updated = true
				err := protobuf.Decode(kv.Value, lvStruct)
				if err != nil {
					log.Errorf("Protobuf decode failed: %v", err)
					break
				}
				ok := lvStruct.authorizeAccess(kv.Name)
				if !ok {
					log.Errorf("Not authorized to insert a value for the key %s", kv.Name)
					break
				}
				if kv.Value == nil || len(kv.Value) == 0 {
					ls.WriteData.KV = append(ls.WriteData.KV[0:i], ls.WriteData.KV[i+1:]...)
					break
				}
				ls.WriteData.KV[i].Value = kv.Value
			}
		}
		if !updated {
			ls.WriteData.KV = append(ls.WriteData.KV, KV{kv.Name, kv.Value})
		}
	}
}

func (lv *CalyLotteryValue) authorizeAccess(key string) bool {
	pk, err := encoding.StringHexToPoint(cothority.Suite, key)
	if err != nil {
		log.Errorf("Converting string to point failed: %v", err)
		return false
	}
	h := sha256.New()
	h.Write(lv.Data)
	err = schnorr.Verify(cothority.Suite, pk, h.Sum(nil), lv.Sig)
	if err != nil {
		log.Errorf("Cannot verify signature: %v", err)
		return false
	}
	return true
}
