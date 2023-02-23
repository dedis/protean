package base

import (
	"crypto/sha256"
	"encoding/binary"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/kyber/v3"
)

const (
	UID  string = "easyrand"
	RAND string = "randomness"
)

type RandomnessInput struct {
	Round uint64
}

type RandomnessOutput struct {
	Public kyber.Point
	Round  uint64
	Prev   []byte
	// Value is the collective signature. Use the hash of it!
	Value []byte
}

func (randInput *RandomnessInput) PrepareHashes() (map[string][]byte, error) {
	inputHashes := make(map[string][]byte)
	inputHashes["round"] = utils.HashUint64(randInput.Round)
	return inputHashes, nil
}

func (randOutput *RandomnessOutput) Hash() ([]byte, error) {
	h := sha256.New()
	buf, err := randOutput.Public.MarshalBinary()
	if err != nil {
		return nil, err
	}
	h.Write(buf)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(randOutput.Round))
	h.Write(b)
	h.Write(randOutput.Prev)
	h.Write(randOutput.Value)
	return h.Sum(nil), nil
}
