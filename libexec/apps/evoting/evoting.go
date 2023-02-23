package evoting

import (
	"github.com/dedis/protean/core"
	easyneff "github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/libexec/base"
	threshold "github.com/dedis/protean/threshold/base"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

func Setup(genInput *base.GenericInput) (*base.GenericOutput, error) {
	input, ok := genInput.I.(SetupInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	kvDict, ok := genInput.KVDicts["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	hdr, err := getHeader(&kvDict)
	if err != nil {
		return nil, err
	}
	hdr.CurrState = "vote_open"
	hdrBuf, err := protobuf.Encode(hdr)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode header: %v", err)
	}
	pkBuf, err := input.Pk.MarshalBinary()
	if err != nil {
		return nil, xerrors.Errorf("marshaling public key: %v", err)
	}
	args := byzcoin.Arguments{
		{Name: "header", Value: hdrBuf},
		{Name: "pk", Value: pkBuf},
	}
	return &base.GenericOutput{O: SetupOutput{WS: args}}, nil
}

func Vote(genInput *base.GenericInput) (*base.GenericOutput, error) {
	input, ok := genInput.I.(VoteInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	kvDict, ok := genInput.KVDicts["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	ballots, err := getBallots(&kvDict)
	if err != nil {
		return nil, err
	}
	ballots.Data.Pairs = append(ballots.Data.Pairs, input.Ballot.Data)
	buf, err := protobuf.Encode(ballots)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode ballots: %v", err)
	}
	args := byzcoin.Arguments{{Name: "enc_ballots", Value: buf}}
	return &base.GenericOutput{O: VoteOutput{WS: args}}, nil
}

func CloseVote(genInput *base.GenericInput) (*base.GenericOutput, error) {
	input, ok := genInput.I.(CloseInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	// Check that the barrier point is passed
	if input.BlkHeight < input.Barrier {
		return nil, xerrors.New("barrier point is not reached yet")
	}
	// Get header
	kvDict, ok := genInput.KVDicts["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	hdr, err := getHeader(&kvDict)
	if err != nil {
		return nil, err
	}
	hdr.CurrState = "vote_closed"
	buf, err := protobuf.Encode(hdr)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode header: %v", err)
	}
	args := byzcoin.Arguments{{Name: "header", Value: buf}}
	return &base.GenericOutput{O: CloseOutput{WS: args}}, nil
}

func PrepareShuffle(genInput *base.GenericInput) (*base.GenericOutput, error) {
	kvDict, ok := genInput.KVDicts["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	ballots, err := getBallots(&kvDict)
	if err != nil {
		return nil, err
	}
	pk, err := getPoint(&kvDict)
	if err != nil {
		return nil, err
	}
	input := easyneff.ShuffleInput{
		Pairs: ballots.Data,
		H:     pk,
	}
	return &base.GenericOutput{O: PrepShufOutput{Input: input}}, nil
}

func PrepareProofs(genInput *base.GenericInput) (*base.GenericOutput, error) {
	input, ok := genInput.I.(PrepProofsInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	prBuf, err := protobuf.Encode(&input.ShProofs)
	if err != nil {
		return nil, xerrors.Errorf("encoding proofs: %v", err)
	}
	// Get header
	kvDict, ok := genInput.KVDicts["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	hdr, err := getHeader(&kvDict)
	if err != nil {
		return nil, err
	}
	hdr.CurrState = "vote_shuffled"
	hdrBuf, err := protobuf.Encode(hdr)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode header: %v", err)
	}
	args := byzcoin.Arguments{
		{Name: "header", Value: hdrBuf},
		{Name: "proofs", Value: prBuf},
	}
	return &base.GenericOutput{O: PrepProofsOutput{WS: args}}, nil
}

func PrepareDecrypt(genInput *base.GenericInput) (*base.GenericOutput, error) {
	kvDict, ok := genInput.KVDicts["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	proofs, err := getProofs(&kvDict)
	if err != nil {
		return nil, err
	}
	sz := len(proofs)
	pairs := proofs[sz-1].Pairs
	input := threshold.DecryptInput{ElGamalPairs: pairs}
	return &base.GenericOutput{O: PrepDecOutput{Input: input}}, nil
}

func Tally(genInput *base.GenericInput) (*base.GenericOutput, error) {
	input, ok := genInput.I.(TallyInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	pdata := make([][]byte, len(input.Ps))
	for i, p := range input.Ps {
		msg, err := p.Data()
		if err != nil {
			return nil, xerrors.Errorf("couldn't recover plaintext: %v", err)
		}
		pdata[i] = msg
	}
	counts := countBallots(pdata, input.CandCount)
	log.Info(counts)
	result := ElectionResult{VoteCounts: counts}
	// Prepare write set
	kvDict, ok := genInput.KVDicts["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	hdr, err := getHeader(&kvDict)
	if err != nil {
		return nil, err
	}
	hdr.CurrState = "vote_finalized"
	hdrBuf, err := protobuf.Encode(hdr)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode header: %v", err)
	}
	decBallots := DecBallots{Data: pdata}
	dbBuf, err := protobuf.Encode(&decBallots)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode decrypted ballots: %v", err)
	}
	resultBuf, err := protobuf.Encode(&result)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode election result: %v", err)
	}
	args := byzcoin.Arguments{
		{Name: "header", Value: hdrBuf},
		{Name: "dec_ballots", Value: dbBuf},
		{Name: "result", Value: resultBuf},
	}
	return &base.GenericOutput{O: TallyOutput{WS: args}}, nil
}

func getHeader(kvDict *core.KVDict) (*core.ContractHeader, error) {
	buf, ok := kvDict.Data["header"]
	if !ok {
		return nil, xerrors.New("missing key: header")
	}
	hdr := &core.ContractHeader{}
	err := protobuf.Decode(buf, hdr)
	if err != nil {
		return nil, xerrors.Errorf("couldn't decode header: %v", err)
	}
	return hdr, nil
}

func getBallots(kvDict *core.KVDict) (*EncBallots, error) {
	buf, ok := kvDict.Data["enc_ballots"]
	if !ok {
		return nil, xerrors.New("missing key: enc_ballots")
	}
	tickets := &EncBallots{}
	err := protobuf.Decode(buf, tickets)
	if err != nil {
		return nil, xerrors.Errorf("couldn't decode ballots: %v", err)
	}
	return tickets, nil
}

func getPoint(kvDict *core.KVDict) (kyber.Point, error) {
	buf, ok := kvDict.Data["pk"]
	if !ok {
		return nil, xerrors.New("missing key: pk")
	}
	pk := cothority.Suite.Point()
	err := pk.UnmarshalBinary(buf)
	if err != nil {
		return nil, xerrors.Errorf("cannot retrieve pk: %v", err)
	}
	return pk, nil
}

func getProofs(kvDict *core.KVDict) ([]easyneff.Proof, error) {
	buf, ok := kvDict.Data["proofs"]
	if !ok {
		return nil, xerrors.New("missing key: proofs")
	}
	shOut := &easyneff.ShuffleOutput{}
	err := protobuf.Decode(buf, shOut)
	if err != nil {
		return nil, xerrors.Errorf("couldn't decode shuffle output: %v", err)
	}
	return shOut.Proofs, nil
}

func countBallots(data [][]byte, candCount int) []int {
	counts := make([]int, candCount)
	for _, ballot := range data {
		v := string(ballot)
		for i := 0; i < candCount; i++ {
			if string(v[i]) == "1" {
				counts[i]++
				break
			}
		}
	}
	return counts
}
