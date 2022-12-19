package playground

import (
	"github.com/dedis/protean/threshold"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

var ContractElGamalID = "elgamal"

type contractElGamal struct {
	byzcoin.BasicContract
	ElGamalStorage
}

func contractElGamalFromBytes(in []byte) (byzcoin.Contract, error) {
	cv := &contractElGamal{}
	err := protobuf.Decode(in, &cv.ElGamalStorage)
	if err != nil {
		return nil, err
	}
	return cv, nil
}

func (c *contractElGamal) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	egs := &c.ElGamalStorage
	req := &ReconstructRequest{}
	rBuf := inst.Spawn.Args.Search("reconstruct")
	if rBuf == nil {
		log.Errorf("Key:reconstruct has no value")
		return
	}
	err = protobuf.Decode(rBuf, req)
	if err != nil {
		log.Errorf("Protobuf decode failed")
		return
	}

	ptList := make([]string, len(req.Cs))
	ps := threshold.RecoverMessages(req.NumNodes, req.Cs, req.Partials)
	for i, p := range ps {
		pt, err := p.Data()
		if err != nil {
			log.Errorf("Cannot get plaintext from curve point: %v", err)
		}
		ptList[i] = string(pt)
	}
	egd := &ElGamalData{
		NumNodes: req.NumNodes,
		Cs:       req.Cs,
		Partials: req.Partials,
		Ps:       ptList,
	}

	egs.Storage = append(egs.Storage, *egd)
	egsBuf, err := protobuf.Encode(&c.ElGamalStorage)
	if err != nil {
		return
	}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Create, inst.DeriveID(""), ContractElGamalID, egsBuf, darcID),
	}
	return
}

//func (c *contractElGamal) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
//cout = coins
//var darcID darc.ID
//_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
//if err != nil {
//return
//}
//if inst.Invoke.Command != "bls" {
//return nil, nil, errors.New("Invoke only works with bls")
//}

//egs := &c.ElGamalStorage
//egd := &ElGamalData{}
//eBuf := inst.Invoke.Args.Search("request")
//if eBuf == nil {
//log.Errorf("Key:request has no value")
//return
//}
//err = protobuf.Decode(eBuf, egd)
//if err != nil {
//log.Errorf("Protobuf decode failed")
//return
//}
//egs.KVStore = append(egs.KVStore, *egd)
//egsBuf, err := protobuf.Encode(&c.ElGamalStorage)
//if err != nil {
//log.Errorf("Protobuf encode error: %v", err)
//return
//}
//sc = []byzcoin.StateChange{
//byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID, ContractElGamalID, egsBuf, darcID),
//}
//return
//}
