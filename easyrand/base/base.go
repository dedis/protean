package base

import (
	"crypto/sha256"
	"encoding/binary"
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

func (randInput *RandomnessInput) PrepareInputHashes() (map[string][]byte, error) {
	inputHashes := make(map[string][]byte)
	h := sha256.New()
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, randInput.Round)
	h.Write(buf)
	inputHashes["round"] = h.Sum(nil)
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
