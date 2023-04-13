package dfu

import (
	"crypto/sha256"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/threshold/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	blsproto "go.dedis.ch/cothority/v3/blscosi/protocol"
	dkgprotocol "go.dedis.ch/cothority/v3/dkg/pedersen"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

func init() {
	_, err := onet.GlobalProtocolRegister(DFUDecryptProtoName, NewThreshDecrypt)
	if err != nil {
		log.Errorf("cannot register protocol: %v", err)
		panic(err)
	}
}

type ThreshDecrypt struct {
	*onet.TreeNodeInstance

	DKGID  [32]byte
	Shared *dkgprotocol.SharedSecret
	Poly   *share.PubPoly

	DecInput       *base.DecryptInput
	KP             *key.Pair
	Ps             []kyber.Point
	OutputReceipts map[string]*core.OpcodeReceipt

	Threshold int
	Failures  int
	Decrypted chan bool

	// private fields
	suite                *pairing.SuiteBn256
	pubShares            map[int]kyber.Point
	partials             []Partial // len(partials) == number of ciphertexts to be dec
	dsResponses          []*DecryptShareResponse
	reconstructResponses []*ReconstructResponse
	mask                 *sign.Mask
	timeout              *time.Timer
	doneOnce             sync.Once
}

func NewThreshDecrypt(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	d := &ThreshDecrypt{
		TreeNodeInstance: n,
		Decrypted:        make(chan bool, 1),
		OutputReceipts:   make(map[string]*core.OpcodeReceipt),
		suite:            pairing.NewSuiteBn256(),
	}
	err := d.RegisterHandlers(d.decryptShare, d.decryptShareResponse,
		d.reconstruct, d.reconstructResponse)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (d *ThreshDecrypt) Start() error {
	log.Lvl3("Starting Protocol")
	if d.Shared == nil {
		d.finish(false)
		return xerrors.New("initialize Shared first")
	}
	if len(d.DecInput.Pairs) == 0 {
		d.finish(false)
		return xerrors.New("empty ciphertext list")
	}
	// First verify the execution request
	d.partials = make([]Partial, len(d.DecInput.Pairs))
	d.pubShares = make(map[int]kyber.Point)
	d.timeout = time.AfterFunc(300*time.Second, func() {
		log.Lvl1("ThreshDecrypt protocol timeout")
		d.finish(false)
	})
	errs := d.SendToChildrenInParallel(&DecryptShare{
		DecryptInput: d.DecInput,
	})
	if len(errs) > (len(d.Roster().List) - d.Threshold) {
		log.Errorf("some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (d *ThreshDecrypt) decryptShare(r structDecryptShare) error {
	d.DecInput = r.DecryptInput
	shares := make([]Share, len(d.DecInput.Pairs))
	for i, c := range d.DecInput.Pairs {
		sh := cothority.Suite.Point().Mul(d.Shared.V, c.K)
		ei, fi := d.generateDecProof(c.K, sh)
		shares[i].Sh = &share.PubShare{I: d.Shared.Index, V: sh}
		shares[i].Ei = ei
		shares[i].Fi = fi
	}
	return d.SendToParent(&DecryptShareResponse{Shares: shares})
}

// decryptShareResponse is the root-node waiting for replies
func (d *ThreshDecrypt) decryptShareResponse(r structDecryptShareResponse) error {
	if len(r.Shares) == 0 {
		log.Lvl2(r.ServerIdentity, "refused to respond")
		d.Failures++
		if d.Failures > (len(d.Roster().List) - d.Threshold) {
			log.Lvl2(r.ServerIdentity, "couldn't get enough shares")
			d.finish(false)
		}
		return nil
	} else {
		// Verify decryption proof
		idx := r.Shares[0].Sh.I
		d.pubShares[idx] = d.Poly.Eval(idx).V
		for i, c := range d.DecInput.Pairs {
			tmpSh := r.Shares[i]
			ok := verifyDecProof(tmpSh.Sh.V, tmpSh.Ei, tmpSh.Fi, c.K,
				d.pubShares[tmpSh.Sh.I])
			if !ok {
				log.Lvl2("received invalid share for ciphertext %d from"+
					" node %d", i, tmpSh.Sh.I)
				d.Failures++
				if d.Failures > len(d.Roster().List)-d.Threshold {
					log.Lvl2(r.ServerIdentity, "couldn't get enough shares")
					d.finish(false)
				}
				return nil
			}
		}
	}

	d.dsResponses = append(d.dsResponses, &r.DecryptShareResponse)

	if len(d.dsResponses) == d.Threshold-1 {
		d.Failures = 0
		idx := -1
		for i, c := range d.DecInput.Pairs {
			// Root prepares its shares
			sh := cothority.Suite.Point().Mul(d.Shared.V, c.K)
			ei, fi := d.generateDecProof(c.K, sh)
			ps := &share.PubShare{I: d.Shared.Index, V: sh}
			d.partials[i].Shares = append(d.partials[i].Shares, ps)
			d.partials[i].Eis = append(d.partials[i].Eis, ei)
			d.partials[i].Fis = append(d.partials[i].Fis, fi)
			for _, rep := range d.dsResponses {
				tmpSh := rep.Shares[i]
				d.partials[i].Shares = append(d.partials[i].Shares, tmpSh.Sh)
				d.partials[i].Eis = append(d.partials[i].Eis, tmpSh.Ei)
				d.partials[i].Fis = append(d.partials[i].Fis, tmpSh.Fi)
			}
			idx = ps.I
		}
		d.pubShares[idx] = d.Poly.Eval(idx).V
		d.Ps = make([]kyber.Point, len(d.partials))
		for i, partial := range d.partials {
			d.Ps[i] = d.recoverCommit(d.DecInput.Pairs[i], partial.Shares)
		}
		// prepare BLS signature and mask
		resp, err := d.generateResponse()
		if err != nil {
			log.Errorf("%s couldn't generate reconstruct response: %v",
				d.Name(), err)
			d.finish(false)
			return err
		}
		d.mask, err = sign.NewMask(d.suite, d.Roster().ServicePublics(blscosi.ServiceName), d.KP.Public)
		if err != nil {
			log.Errorf("couldn't generate mask: %v", err)
			d.finish(false)
			return err
		}
		// add root's reconstruct response to the array
		d.reconstructResponses = append(d.reconstructResponses, resp)
		errs := d.SendToChildrenInParallel(&Reconstruct{
			Threshold: d.Threshold,
			Partials:  d.partials,
			Publics:   d.pubShares,
		})
		if len(errs) > (len(d.Roster().List) - d.Threshold) {
			log.Errorf("some nodes failed with error(s) %v", errs)
			d.finish(false)
		}
	}
	return nil
}

func (d *ThreshDecrypt) reconstruct(r structReconstruct) error {
	defer d.Done()
	d.Threshold = r.Threshold
	if d.DecInput == nil {
		log.Info("%s missing input", d.ServerIdentity().String())
		return cothority.ErrorOrNil(d.SendToParent(&ReconstructResponse{}),
			"sending ReconstructResponse to parent")
	}
	d.Ps = make([]kyber.Point, len(r.Partials))
	for i, c := range d.DecInput.Pairs {
		partial := r.Partials[i]
		for j, _ := range partial.Shares {
			ok := verifyDecProof(partial.Shares[j].V, partial.Eis[j],
				partial.Fis[j], c.K, r.Publics[partial.Shares[j].I])
			if !ok {
				log.Errorf("%s couldn't verify decryption proof", d.Name())
				return cothority.ErrorOrNil(d.SendToParent(&ReconstructResponse{}),
					"sending ReconstructResponse to parent")
			}
		}
		d.Ps[i] = d.recoverCommit(c, partial.Shares)
	}
	resp, err := d.generateResponse()
	if err != nil {
		log.Errorf("%s couldn't generate reconstruct response: %v", d.Name(), err)
	}
	return cothority.ErrorOrNil(d.SendToParent(resp),
		"sending ReconstructResponse to parent")
}

func (d *ThreshDecrypt) reconstructResponse(r structReconstructResponse) error {
	index := utils.SearchPublicKey(d.TreeNodeInstance, r.ServerIdentity)
	if len(r.Signatures) == 0 || index < 0 {
		log.Lvl2(r.ServerIdentity, "refused to send back reconstruct response")
		d.Failures++
		if d.Failures > (len(d.Roster().List) - d.Threshold) {
			log.Lvl2(r.ServerIdentity, "couldn't get enough reconstruct responses")
			d.finish(false)
		}
		return nil
	}

	d.mask.SetBit(index, true)
	d.reconstructResponses = append(d.reconstructResponses, &r.ReconstructResponse)
	if len(d.reconstructResponses) == d.Threshold {
		for name, receipt := range d.OutputReceipts {
			aggSignature := d.suite.G1().Point()
			for _, resp := range d.reconstructResponses {
				sig, err := resp.Signatures[name].Point(d.suite)
				if err != nil {
					d.finish(false)
					return err
				}
				aggSignature = aggSignature.Add(aggSignature, sig)
			}
			sig, err := aggSignature.MarshalBinary()
			if err != nil {
				d.finish(false)
				return err
			}
			receipt.Sig = append(sig, d.mask.Mask()...)
		}
		d.finish(true)
	}
	return nil
}

func (d *ThreshDecrypt) generateResponse() (*ReconstructResponse, error) {
	sigs := make(map[string]blsproto.BlsSignature)
	hash, err := utils.HashPoints(d.Ps)
	if err != nil {
		log.Errorf("calculating the hash of points: %v", err)
		return &ReconstructResponse{}, err
	}
	r := &core.OpcodeReceipt{
		EPID:      make([]byte, 32),
		OpIdx:     0,
		Name:      "plaintexts",
		HashBytes: hash,
	}
	if d.IsRoot() {
		d.OutputReceipts["plaintexts"] = r
	}
	sig, err := bls.Sign(d.suite, d.KP.Private, r.Hash())
	if err != nil {
		return &ReconstructResponse{}, err
	}
	sigs["plaintexts"] = sig
	return &ReconstructResponse{Signatures: sigs}, nil
}

func (d *ThreshDecrypt) generateDecProof(u kyber.Point, sh kyber.Point) (kyber.Scalar, kyber.Scalar) {
	si := cothority.Suite.Scalar().Pick(d.Suite().RandomStream())
	uiHat := cothority.Suite.Point().Mul(si, u)
	hiHat := cothority.Suite.Point().Mul(si, nil)
	hash := sha256.New()
	sh.MarshalTo(hash)
	uiHat.MarshalTo(hash)
	hiHat.MarshalTo(hash)
	ei := cothority.Suite.Scalar().SetBytes(hash.Sum(nil))
	fi := cothority.Suite.Scalar().Add(si, cothority.Suite.Scalar().Mul(ei, d.Shared.V))
	return ei, fi
}

func verifyDecProof(sh kyber.Point, ei kyber.Scalar, fi kyber.Scalar,
	u kyber.Point, pub kyber.Point) bool {
	// sh = ui // u = g^r // pub = h^i
	//Verify proofs
	ufi := cothority.Suite.Point().Mul(fi, u)
	uiei := cothority.Suite.Point().Mul(cothority.Suite.Scalar().Neg(ei), sh)
	uiHat := cothority.Suite.Point().Add(ufi, uiei)
	gfi := cothority.Suite.Point().Mul(fi, nil)
	hiei := cothority.Suite.Point().Mul(cothority.Suite.Scalar().Neg(ei), pub)
	hiHat := cothority.Suite.Point().Add(gfi, hiei)
	hash := sha256.New()
	sh.MarshalTo(hash)
	uiHat.MarshalTo(hash)
	hiHat.MarshalTo(hash)
	e := cothority.Suite.Scalar().SetBytes(hash.Sum(nil))
	return e.Equal(ei)
}

func (d *ThreshDecrypt) recoverCommit(cs utils.ElGamalPair, pubShares []*share.PubShare) kyber.Point {
	rc, err := share.RecoverCommit(cothority.Suite, pubShares, d.Threshold, len(d.List()))
	if err != nil {
		log.Errorf("couldn't recover message: %v", err)
		return nil
	}
	p := cothority.Suite.Point().Sub(cs.C, rc)
	return p
}

func (d *ThreshDecrypt) finish(result bool) {
	d.timeout.Stop()
	select {
	case d.Decrypted <- result:
		// succeeded
	default:
		// would have blocked because some other call to finish()
		// beat us.
	}
	d.doneOnce.Do(func() { d.Done() })
}
