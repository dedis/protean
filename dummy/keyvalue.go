package dummy

import (
	"errors"

	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

const ContractKeyValueID = "keyValue"

type contractValue struct {
	byzcoin.BasicContract
	Storage
}

func contractValueFromBytes(in []byte) (byzcoin.Contract, error) {
	log.Info("========== CEY: CONTRACT VALUE FROM BYTES ========")
	cv := &contractValue{}
	err := protobuf.Decode(in, &cv.Storage)
	if err != nil {
		log.Errorf("Protobuf decode failed: %v", err)
		return nil, err
	}
	if cv.Storage.Data == nil {
		cv.Storage.Data = make(map[string][]byte)
	}
	return cv, nil
}

func (c *contractValue) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	log.Info("========== CEY: SPAWN ========")
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}
	cs := &c.Storage
	for _, kv := range inst.Spawn.Args {
		//cs.Data = append(cs.Data, KV{kv.Name, kv.Value})
		cs.Data[kv.Name] = kv.Value
	}

	csBuf, err := protobuf.Encode(&c.Storage)
	if err != nil {
		return
	}

	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Create, inst.DeriveID(""), ContractKeyValueID, csBuf, darcID),
	}
	return
}

func (c *contractValue) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	log.Info("========== CEY: INVOKE ========")
	cout = coins
	var darcID darc.ID
	log.Info("========== CEY: INVOKE.GETVALUES ========")
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		log.Errorf("Get values failed: %v", err)
		return
	}

	if inst.Invoke.Command != "update" {
		log.Errorf("Value contract can only update")
		return nil, nil, errors.New("Value contract can only update")
	}

	kvd := &c.Storage
	log.Info("========== CEY: INVOKE.UPDATE ========")
	kvd.Update(inst.Invoke.Args)
	var buf []byte
	buf, err = protobuf.Encode(kvd)
	if err != nil {
		log.Errorf("protobuf encode failed: %v", err)
		return
	}
	log.Info("========== CEY: INVOKE.STATECHANGE ========")
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID, ContractKeyValueID, buf, darcID),
	}
	return

}

func (c *contractValue) Delete(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		log.Errorf("Get values failed in Delete: %v", err)
		return
	}

	sc = byzcoin.StateChanges{byzcoin.NewStateChange(byzcoin.Remove, inst.InstanceID, ContractKeyValueID, nil, darcID)}
	return
}

func (cs *Storage) Update(args byzcoin.Arguments) {
	for _, arg := range args {
		var updated bool
		for key, value := range cs.Data {
			if key == arg.Name {
				updated = true
				if value == nil || len(value) == 0 {
					delete(cs.Data, key)
					break
				}
				cs.Data[arg.Name] = arg.Value
			}
		}
		if !updated {
			cs.Data[arg.Name] = arg.Value
		}
	}
}

//func (cs *Storage) Update(args byzcoin.Arguments) {
//for _, kv := range args {
//var updated bool
//for i, stored := range cs.Data {
//if stored.Key == kv.Name {
//updated = true
//if kv.Value == nil || len(kv.Value) == 0 {
//cs.Data = append(cs.Data[0:i], cs.Data[i+1:]...)
//break
//}
//cs.Data[i].Value = kv.Value
//}
//}
//if !updated {
//cs.Data = append(cs.Data, KV{kv.Name, kv.Value})
//}
//}
//}

//func (cs *KVStorage) Update(args byzcoin.Arguments) {
//for _, kv := range args {
//var updated bool
//for i, stored := range cs.Storage {
//if stored.Key == kv.Name {
//updated = true
//if kv.Value == nil || len(kv.Value) == 0 {
//cs.Storage = append(cs.Storage[0:i], cs.Storage[i+1:]...)
//break
//}
//cs.Storage[i].Value = kv.Value
//}
//}
//if !updated {
//cs.Storage = append(cs.Storage, &KeyValue{kv.Name, kv.Value})
//}
//}
//}
