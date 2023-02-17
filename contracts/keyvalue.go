package contracts

import (
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

const ContractKeyValueID = "keyValue"

type KV struct {
	Key   string
	Value []byte
}

// Storage holds the contract state. Store[0] stores the header (i.e. Store[0].
// Key == "header"). The stored value is a protobuf-encoded core. ContractHeader
// struct.
type Storage struct {
	Store []KV
}
type ContractKeyValue struct {
	byzcoin.BasicContract
	Storage
}

func ContractKeyValueFromBytes(in []byte) (byzcoin.Contract, error) {
	cv := &ContractKeyValue{}
	err := protobuf.Decode(in, &cv.Storage)
	if err != nil {
		log.Errorf("Protobuf decode failed: %v", err)
		return nil, err
	}
	return cv, nil
}

func (c *ContractKeyValue) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		log.Errorf("GetValues failed: %v", err)
		return
	}
	cs := &c.Storage
	for _, kv := range inst.Spawn.Args {
		cs.Store = append(cs.Store, KV{kv.Name, kv.Value})
		//cs.Store = append(cs.Store, KV{Key: kv.Name, Value: kv.Value, Version: 0})
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

func (c *ContractKeyValue) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		log.Errorf("Get values failed: %v", err)
		return
	}
	if inst.Invoke.Command != "update" {
		log.Errorf("Value contract can only update")
		return nil, nil, xerrors.New("value contract can only update")
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

func (c *ContractKeyValue) Delete(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
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
		var updated bool
		for i, stored := range cs.Store {
			if stored.Key == kv.Name {
				updated = true
				if kv.Value == nil || len(kv.Value) == 0 {
					cs.Store = append(cs.Store[0:i], cs.Store[i+1:]...)
					break
				}
				cs.Store[i].Value = kv.Value
			}
		}
		if !updated {
			cs.Store = append(cs.Store, KV{Key: kv.Name, Value: kv.Value})
		}
	}
}
