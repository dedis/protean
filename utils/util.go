package utils

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

var ps = pairing.NewSuiteBn256()

func StoreBlock(s *skipchain.Service, genesis skipchain.SkipBlockID, data []byte) error {
	db := s.GetDB()
	latest, err := db.GetLatest(db.GetByID(genesis))
	if err != nil {
		log.Errorf("[StoreBlock] Could not find the latest block: %v", err)
		return err
	}
	block := latest.Copy()
	block.Data = data
	block.GenesisID = block.SkipChainID()
	block.Index++
	_, err = s.StoreSkipBlock(&skipchain.StoreSkipBlock{
		NewBlock:          block,
		TargetSkipChainID: latest.SkipChainID(),
	})
	if err != nil {
		log.Errorf("[StoreBlock] Could not store skipclock: %v", err)
	}
	return err
}

func CreateGenesisBlock(s *skipchain.Service, scData *ScInitData) (*skipchain.StoreSkipBlockReply, error) {
	genesis := skipchain.NewSkipBlock()
	genesis.MaximumHeight = scData.MHeight
	genesis.BaseHeight = scData.BHeight
	genesis.Roster = scData.Roster
	genesis.VerifierIDs = skipchain.VerificationStandard
	reply, err := s.StoreSkipBlock(&skipchain.StoreSkipBlock{
		NewBlock: genesis,
	})
	if err != nil {
		log.Errorf("[CreateGenesisBlock] Could not store skipblock: %v", err)
	}
	return reply, err
}

func VerifySignature(s interface{}, sig protocol.BlsSignature, publics []kyber.Point) error {
	data, err := protobuf.Encode(s)
	if err != nil {
		log.Errorf("protobuf encode failed: %v", err)
		return err
	}
	h := sha256.New()
	h.Write(data)
	return sig.Verify(ps, h.Sum(nil), publics)
}

func GetServerKey(fname *string) (kyber.Point, error) {
	var keys []kyber.Point
	fh, err := os.Open(*fname)
	defer fh.Close()
	if err != nil {
		log.Errorf("GetServerKey error: %v", err)
		return nil, err
	}

	fs := bufio.NewScanner(fh)
	for fs.Scan() {
		tmp, err := encoding.StringHexToPoint(cothority.Suite, fs.Text())
		if err != nil {
			log.Errorf("GetServerKey error: %v", err)
			return nil, err
		}
		keys = append(keys, tmp)
	}
	return keys[0], nil
}

func ReadRoster(path *string) (*onet.Roster, error) {
	file, err := os.Open(*path)
	if err != nil {
		log.Errorf("ReadRoster error: %v", err)
		return nil, err
	}

	group, err := app.ReadGroupDescToml(file)
	if err != nil {
		log.Errorf("ReadRoster error: %v", err)
		return nil, err
	}

	if len(group.Roster.List) == 0 {
		fmt.Println("Empty roster")
		log.Errorf("ReadRoster error: %v", err)
		return nil, err
	}
	return group.Roster, nil
}
