package dummy

import (
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

const ContractLotteryID = "lottery"

type contractLottery struct {
	byzcoin.BasicContract
	LotteryStorage
}

func contractLotteryFromBytes(in []byte) (byzcoin.Contract, error) {
	cv := &contractLottery{}
	err := protobuf.Decode(in, &cv.LotteryStorage)
	if err != nil {
		log.Errorf("Protobuf decode failed: %v", err)
		return nil, err
	}
	return cv, nil
}

func (c *contractLottery) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		log.Errorf("GetValues failed: %v", err)
		return
	}
	ls := &c.LotteryStorage
	lvStruct := &LotteryValue{}
	for _, kv := range inst.Spawn.Args {
		err = protobuf.Decode(kv.Value, lvStruct)
		if err != nil {
			log.Errorf("Protobuf decode failed: %v", err)
			return
		}
		ok := authorizeAccess(kv.Name, lvStruct)
		if !ok {
			log.Errorf("Not authorized to insert a value for the key %s", kv.Name)
			return
		}
		ls.Storage = append(ls.Storage, KV{kv.Name, kv.Value})
	}
	lsBuf, err := protobuf.Encode(&c.LotteryStorage)
	if err != nil {
		log.Errorf("Protobuf encode failed: %v", err)
		return
	}
	//for _, kv := range inst.Spawn.Args {
	//ls.Storage = append(ls.Storage, KV{kv.Name, kv.Value})
	//}
	//lsBuf, err := protobuf.Encode(&c.LotteryStorage)
	//if err != nil {
	//log.Errorf("Protobuf encode failed: %v", err)
	//return
	//}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Create, inst.DeriveID(""), ContractLotteryID, lsBuf, darcID),
	}
	return
}

func (c *contractLottery) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		log.Errorf("Get values failed: %v", err)
		return
	}
	if inst.Invoke.Command != "update" {
		log.Errorf("Value contract can only update")
		return nil, nil, fmt.Errorf("Value contract can only update")
	}
	kvd := &c.LotteryStorage
	kvd.Update(inst.Invoke.Args)
	var buf []byte
	buf, err = protobuf.Encode(kvd)
	if err != nil {
		log.Errorf("Protobuf encode failed: %v", err)
		return
	}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID, ContractLotteryID, buf, darcID),
	}
	return
}

func (c *contractLottery) Delete(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		log.Errorf("Get values failed: %v", err)
		return
	}

	sc = byzcoin.StateChanges{byzcoin.NewStateChange(byzcoin.Remove, inst.InstanceID, ContractLotteryID, nil, darcID)}
	return
}

func (ls *LotteryStorage) Update(args byzcoin.Arguments) {
	lvStruct := &LotteryValue{}
	for _, kv := range args {
		updated := false
		for i, stored := range ls.Storage {
			if stored.Key == kv.Name {
				updated = true
				err := protobuf.Decode(kv.Value, lvStruct)
				if err != nil {
					log.Errorf("Protobuf decode failed: %v", err)
					break
				}
				ok := authorizeAccess(kv.Name, lvStruct)
				if !ok {
					log.Errorf("Not authorized to insert a value for the key %s", kv.Name)
					break
				}
				if kv.Value == nil || len(kv.Value) == 0 {
					ls.Storage = append(ls.Storage[0:i], ls.Storage[i+1:]...)
					break
				}
				ls.Storage[i].Value = kv.Value
			}
		}
		if !updated {
			ls.Storage = append(ls.Storage, KV{kv.Name, kv.Value})
		}
	}
}

func authorizeAccess(key string, lv *LotteryValue) bool {
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
