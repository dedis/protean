package state

import (
	"fmt"

	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

const ContractKeyValueID = "keyValue"

type Storage struct {
	Data []KV
}

type contractValue struct {
	byzcoin.BasicContract
	Storage
}

func contractValueFromBytes(in []byte) (byzcoin.Contract, error) {
	cv := &contractValue{}
	err := protobuf.Decode(in, &cv.Storage)
	if err != nil {
		log.Errorf("Protobuf decode failed: %v", err)
		return nil, err
	}
	return cv, nil
}

func (c *contractValue) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		log.Errorf("GetValues failed: %v", err)
		return
	}
	cs := &c.Storage
	for _, kv := range inst.Spawn.Args {
		//cs.Data = append(cs.Data, KV{kv.Name, kv.Value})
		cs.Data = append(cs.Data, KV{Key: kv.Name, Value: kv.Value, Version: 0})
	}
	csBuf, err := protobuf.Encode(&c.Storage)
	if err != nil {
		log.Errorf("Protobuf encode failed: %v", err)
		return
	}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Create, inst.DeriveID(""), ContractKeyValueID, csBuf, darcID),
	}
	return
}

func (c *contractValue) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
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
	kvd := &c.Storage
	kvd.Update(inst.Invoke.Args)
	var buf []byte
	buf, err = protobuf.Encode(kvd)
	if err != nil {
		log.Errorf("Protobuf encode failed: %v", err)
		return
	}
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
		log.Errorf("Get values failed: %v", err)
		return
	}

	sc = byzcoin.StateChanges{byzcoin.NewStateChange(byzcoin.Remove, inst.InstanceID, ContractKeyValueID, nil, darcID)}
	return
}

func (cs *Storage) Update(args byzcoin.Arguments) {
	for _, kv := range args {
		updated := false
		for i, stored := range cs.Data {
			if stored.Key == kv.Name {
				updated = true
				if kv.Value == nil || len(kv.Value) == 0 {
					cs.Data = append(cs.Data[0:i], cs.Data[i+1:]...)
					break
				}
				cs.Data[i].Value = kv.Value
				//TODO: Make sure this does not break things
				cs.Data[i].Version++
			}
		}
		if !updated {
			//cs.Data = append(cs.Data, KV{kv.Name, kv.Value})
			cs.Data = append(cs.Data, KV{Key: kv.Name, Value: kv.Value, Version: 0})
		}
	}
}
