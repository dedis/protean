package threshold

import (
	"errors"
	"sync"
	"time"

	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	dkgprotocol "go.dedis.ch/cothority/v3/dkg/pedersen"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	_, err := onet.GlobalProtocolRegister(ThreshProtoName, NewThreshDecrypt)
	if err != nil {
		log.Errorf("Cannot register protocol: %v", err)
		panic(err)
	}
	network.RegisterMessages(&PartialRequest{}, &PartialReply{})
}

type ThreshDecrypt struct {
	*onet.TreeNodeInstance
	Shared    *dkgprotocol.SharedSecret
	Cs        []*utils.ElGamalPair
	Partials  []*Partial
	Threshold int
	Failures  int
	Decrypted chan bool
	// private fields
	replies  []PartialReply
	timeout  *time.Timer
	doneOnce sync.Once
}

func NewThreshDecrypt(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	d := &ThreshDecrypt{
		TreeNodeInstance: n,
		Decrypted:        make(chan bool, 1),
		Threshold:        len(n.Roster().List) - (len(n.Roster().List)-1)/3,
	}
	err := d.RegisterHandlers(d.decrypt, d.decryptReply)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (d *ThreshDecrypt) Start() error {
	log.Lvl3("Starting Protocol")
	if d.Shared == nil {
		d.finish(false)
		return errors.New("Initialize Shared first")
	}
	if len(d.Cs) == 0 {
		d.finish(false)
		return errors.New("Empty ciphertext list")
	}
	pd := &PartialRequest{
		Cs: d.Cs,
	}
	d.timeout = time.AfterFunc(1*time.Minute, func() {
		log.Lvl1("ThreshDecrypt protocol timeout")
		d.finish(false)
	})
	errs := d.Broadcast(pd)
	if len(errs) > (len(d.Roster().List)-1)/3 {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return errors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (d *ThreshDecrypt) decrypt(r structPartialRequest) error {
	log.Lvl3(d.Name() + ": starting decrypt")
	defer d.Done()

	shares := make([]kyber.Point, len(r.Cs))
	for i, c := range r.Cs {
		shares[i] = utils.ElGamalDecrypt(d.Shared.V, c)
	}

	// Calculating proofs
	//si := cothority.Suite.Scalar().Pick(d.Suite().RandomStream())
	//uiHat := cothority.Suite.Point().Mul(si, r.Ciphertext.C1)
	//hiHat := cothority.Suite.Point().Mul(si, nil)
	//hash := sha256.New()
	//S.MarshalTo(hash)
	//uiHat.MarshalTo(hash)
	//hiHat.MarshalTo(hash)
	//ei := cothority.Suite.Scalar().SetBytes(hash.Sum(nil))

	return d.SendToParent(&PartialReply{
		Index:  d.Shared.Index,
		Shares: shares,
	})
}

// decryptReply is the root-node waiting for all replies
func (d *ThreshDecrypt) decryptReply(pdr structPartialReply) error {
	if pdr.PartialReply.Shares == nil {
		log.Lvl2("Node", pdr.ServerIdentity, "refused to reply")
		d.Failures++
		if d.Failures > len(d.Roster().List)-d.Threshold {
			log.Lvl2(pdr.ServerIdentity, "couldn't get enough shares")
			d.finish(false)
		}
		return nil
	}
	d.replies = append(d.replies, pdr.PartialReply)

	// minus one to exclude the root
	if len(d.replies) >= int(d.Threshold-1) {
		//d.Partials = make([]*Partial, len(d.Cs))
		for i := 0; i < len(d.Cs); i++ {
			d.Partials = append(d.Partials, &Partial{
				Shares: make([]kyber.Point, len(d.List())),
			})
		}
		for i, c := range d.Cs {
			share := utils.ElGamalDecrypt(d.Shared.V, c)
			d.Partials[i].Shares[d.Shared.Index] = share
		}
		for _, r := range d.replies {
			// Verify proofs
			//var ufi kyber.Point
			//if d.Xc == nil {
			//ufi = cothority.Suite.Point().Mul(r.Fi, d.U)
			//} else {
			//ufi = cothority.Suite.Point().Mul(r.Fi, cothority.Suite.Point().Add(d.U, d.Xc))
			//}
			//uiei := cothority.Suite.Point().Mul(cothority.Suite.Scalar().Neg(r.Ei), r.Ui.V)
			//uiHat := cothority.Suite.Point().Add(ufi, uiei)
			//gfi := cothority.Suite.Point().Mul(r.Fi, nil)
			//gxi := d.Poly.Eval(r.Ui.I).V
			//hiei := cothority.Suite.Point().Mul(cothority.Suite.Scalar().Neg(r.Ei), gxi)
			//hiHat := cothority.Suite.Point().Add(gfi, hiei)
			//hash := sha256.New()
			//r.Ui.V.MarshalTo(hash)
			//uiHat.MarshalTo(hash)
			//hiHat.MarshalTo(hash)
			//e := cothority.Suite.Scalar().SetBytes(hash.Sum(nil))
			//if e.Equal(r.Ei) {
			//d.Uis[r.Ui.I] = r.Ui
			//} else {
			//log.Lvl1("Received invalid share from node", r.Ui.I)
			//}

			if r.Shares != nil && len(r.Shares) == len(d.Cs) {
				for i, s := range r.Shares {
					d.Partials[i].Shares[r.Index] = s
				}
			} else {
				log.Lvl1("Received invalid share from node", r.Index)
			}
		}
		d.finish(true)
	}
	// If we are leaving by here it means that we do not have
	// enough replies yet. We must eventually trigger a finish()
	// somehow. It will either happen because we get another
	// reply, and now we have enough, or because we get enough
	// failures and know to give up, or because d.timeout triggers
	// and calls finish(false) in it's callback function.
	return nil
}

func (d *ThreshDecrypt) getUI(U, Xc kyber.Point) (*share.PubShare, error) {
	v := cothority.Suite.Point().Mul(d.Shared.V, U)
	if Xc != nil {
		v.Add(v, cothority.Suite.Point().Mul(d.Shared.V, Xc))
	}
	return &share.PubShare{I: d.Shared.Index, V: v}, nil
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
