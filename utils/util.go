package utils

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	//"github.com/ceyhunalp/protean_code/compiler"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	//"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"os"
	//"strconv"
	//"strings"
)

var ps = pairing.NewSuiteBn256()

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
