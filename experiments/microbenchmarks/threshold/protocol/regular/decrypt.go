package regular

import (
	"crypto/sha256"
	"github.com/dedis/protean/threshold/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	dkgprotocol "go.dedis.ch/cothority/v3/dkg/pedersen"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

func init() {
	_, err := onet.GlobalProtocolRegister(RegularDecryptProtoName, NewThreshDecrypt)
	if err != nil {
		log.Errorf("cannot register protocol: %v", err)
		panic(err)
	}
}

type ThreshDecrypt struct {
	*onet.TreeNodeInstance

	DKGID    [32]byte
	Shared   *dkgprotocol.SharedSecret
	Poly     *share.PubPoly
	DecInput *base.DecryptInput

	Threshold int
	Failures  int
	Partials  []Partial // len(partials) == number of ciphertexts to be dec
	Decrypted chan bool

	// private fields
	suite       *pairing.SuiteBn256
	dsResponses []*DecryptShareResponse
	mask        *sign.Mask
	timeout     *time.Timer
	doneOnce    sync.Once
}

func NewThreshDecrypt(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	d := &ThreshDecrypt{
		TreeNodeInstance: n,
		Decrypted:        make(chan bool, 1),
		suite:            pairing.NewSuiteBn256(),
	}
	err := d.RegisterHandlers(d.decryptShare, d.decryptShareResponse)
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
	d.Partials = make([]Partial, len(d.DecInput.Pairs))
	//d.pubShares = make(map[int]kyber.Point)
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
		pub := d.Poly.Eval(idx).V
		for i, c := range d.DecInput.Pairs {
			tmpSh := r.Shares[i]
			ok := verifyDecProof(tmpSh.Sh.V, tmpSh.Ei, tmpSh.Fi, c.K, pub)
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

	if len(d.dsResponses) >= d.Threshold-1 {
		pub := d.Poly.Eval(d.Shared.Index).V
		for i, c := range d.DecInput.Pairs {
			// Root prepares its shares
			sh := cothority.Suite.Point().Mul(d.Shared.V, c.K)
			ei, fi := d.generateDecProof(c.K, sh)
			ps := &share.PubShare{I: d.Shared.Index, V: sh}
			d.Partials[i].Shares = append(d.Partials[i].Shares, ps)
			d.Partials[i].Eis = append(d.Partials[i].Eis, ei)
			d.Partials[i].Fis = append(d.Partials[i].Fis, fi)
			d.Partials[i].Pubs = append(d.Partials[i].Pubs, pub)
		}

		pubs := make([]kyber.Point, len(d.List()))
		for _, resp := range d.dsResponses {
			idx := resp.Shares[0].Sh.I
			pubs[idx] = d.Poly.Eval(idx).V
		}

		for i, _ := range d.DecInput.Pairs {
			for _, resp := range d.dsResponses {
				tmpSh := resp.Shares[i]
				d.Partials[i].Shares = append(d.Partials[i].Shares, tmpSh.Sh)
				d.Partials[i].Eis = append(d.Partials[i].Eis, tmpSh.Ei)
				d.Partials[i].Fis = append(d.Partials[i].Fis, tmpSh.Fi)
				d.Partials[i].Pubs = append(d.Partials[i].Pubs, pubs[tmpSh.Sh.I])
			}
		}
		d.finish(true)
	}
	return nil
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
