package base

import "github.com/dedis/protean/utils"

const (
	UID string = "threshold"
	DKG string = "init_dkg"
	DEC string = "decrypt"
)

type DecryptInput struct {
	utils.ElGamalPairs
}

func (decInput *DecryptInput) prepareInputHashes() (map[string][]byte, error) {
	inputHashes := make(map[string][]byte)
	hash, err := decInput.Hash()
	if err != nil {
		return nil, err
	}
	inputHashes["ciphertexts"] = hash
	return inputHashes, nil
}
