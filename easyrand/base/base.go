package base

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	UID  string = "easyrand"
	RAND string = "Randomness"
)

type RandomnessInput struct {
	Round uint64
}

func (randInput *RandomnessInput) prepareInputHashes() (map[string][]byte, error) {
	inputHashes := make(map[string][]byte)
	h := sha256.New()
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, randInput.Round)
	h.Write(buf)
	inputHashes["round"] = h.Sum(nil)
	return inputHashes, nil
}
