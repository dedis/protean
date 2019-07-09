package state

import (
	"errors"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/protobuf"
)

const ContractKeyValueID = "keyValue"

type contractValue struct {
	byzcoin.BasicContract
	KVData
}

func contractValueFromBytes(in []byte) (byzcoin.Contract, error) {
	cv := &contractValue{}
	err := protobuf.Decode(in, &cv.KVData)
	if err != nil {
		return nil, err
	}
	return cv, nil
}

func (c *contractValue) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	cs := &c.KVData
	for _, kv := range inst.Spawn.Args {
		cs.Storage = append(cs.Storage, &KeyValue{kv.Name, kv.Value})
	}

	csBuf, err := protobuf.Encode(&c.KVData)
	if err != nil {
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
		return
	}

	if inst.Invoke.Command != "update" {
		return nil, nil, errors.New("Value contract can only update")
	}

	kvd := &c.KVData
	kvd.Update(inst.Invoke.Args)
	var buf []byte
	buf, err = protobuf.Encode(kvd)
	if err != nil {
		return
	}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID, ContractKeyValueID, buf, darcID),
	}
	return

}

func (cs *KVData) Update(args byzcoin.Arguments) {
	for _, kv := range args {
		var updated bool
		for i, stored := range cs.Storage {
			if stored.Key == kv.Name {
				updated = true
				if kv.Value == nil || len(kv.Value) == 0 {
					cs.Storage = append(cs.Storage[0:i], cs.Storage[i+1:]...)
					break
				}
				cs.Storage[i].Value = kv.Value
			}
		}
		if !updated {
			cs.Storage = append(cs.Storage, &KeyValue{kv.Name, kv.Value})
		}
	}
}
