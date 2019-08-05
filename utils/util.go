package utils

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"

	protean "github.com/ceyhunalp/protean_code"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

var ps = pairing.NewSuiteBn256()

func BlsCosiSign(s *blscosi.Service, r *onet.Roster, data []byte) (network.Message, error) {
	h := sha256.New()
	h.Write(data)
	resp, err := s.SignatureRequest(&blscosi.SignatureRequest{
		Message: h.Sum(nil),
		Roster:  r,
	})
	return resp, err
}

func StoreBlock(s *skipchain.Service, genesis skipchain.SkipBlockID, data []byte) error {
	log.Infof("In StoreBlock service id is: %s", s.ServiceID())
	db := s.GetDB()
	latest, err := db.GetLatest(db.GetByID(genesis))
	if err != nil {
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
	return err
}

func CreateGenesisBlock(s *skipchain.Service, scData *protean.ScInitData) (*skipchain.StoreSkipBlockReply, error) {
	log.Infof("[CreateGenesisBlock] Service: %s", s.ServiceID())
	genesis := skipchain.NewSkipBlock()
	genesis.MaximumHeight = scData.MHeight
	genesis.BaseHeight = scData.BHeight
	genesis.Roster = scData.Roster
	genesis.VerifierIDs = skipchain.VerificationStandard
	reply, err := s.StoreSkipBlock(&skipchain.StoreSkipBlock{
		NewBlock: genesis,
	})
	return reply, err
}

func VerifySignature(s interface{}, sig protocol.BlsSignature, publics []kyber.Point) error {
	data, err := protobuf.Encode(s)
	if err != nil {
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
