package sys

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

//TODO: Curently there is a single roster and every unit uses the same roster.
//Each line in the units.txt file should specify the number of nodes in that
//unit. Then we can parse a single roster file, using the node count information
//to determine where a new roster starts. (Potentially use onet.NewRoster)
func PrepareUnits(roster *onet.Roster, uFilePtr *string) ([]*FunctionalUnit, error) {
	var fus []UnitJSON
	fh, err := os.Open(*uFilePtr)
	if err != nil {
		log.Errorf("Cannot open file %s: %v", *uFilePtr, err)
		return nil, err
	}
	defer fh.Close()
	buf, err := ioutil.ReadAll(fh)
	if err != nil {
		log.Errorf("Error reading file %s: %v", *uFilePtr, err)
		return nil, err
	}
	err = json.Unmarshal(buf, &fus)
	if err != nil {
		log.Errorf("Cannot unmarshal json value: %v", err)
		return nil, err
	}
	sz := len(fus)
	units := make([]*FunctionalUnit, sz)
	for i := 0; i < sz; i++ {
		tmp := fus[i]
		units[i] = &FunctionalUnit{
			Type:     tmp.Type,
			Name:     tmp.Name,
			NumNodes: tmp.NumNodes,
			Txns:     tmp.Txns,
			Roster:   roster,
			Publics:  roster.Publics(),
		}
		//TODO: Revert to ServicePublics() once you have the suitable
		//roster.toml file generated
		//sn := fus[i].Name + "Service"
		//fus[i].Publics = roster.ServicePublics(sn)
		//units[i] = &fus[i]
	}
	return units, nil
}

func VerifyAuthentication(mesg []byte, wf *Workflow, sigMap map[string][]byte) error {
	if len(sigMap) == 0 {
		log.LLvlf1("Workflow does not have authorized users")
		return nil
	}
	if wf.All {
		for id, authPub := range wf.AuthPublics {
			sig, ok := sigMap[id]
			if !ok {
				return fmt.Errorf("Missing signature from %v", id)
			}
			err := schnorr.Verify(cothority.Suite, authPub, mesg, sig)
			if err != nil {
				return fmt.Errorf("Cannot verify signature from %v", id)
			}
		}
	} else {
		success := false
		for id, sig := range sigMap {
			pk, ok := wf.AuthPublics[id]
			if !ok {
				return fmt.Errorf("Cannot find %v in authenticated users", id)
			}
			err := schnorr.Verify(cothority.Suite, pk, mesg, sig)
			if err == nil {
				success = true
				break
			}
		}
		if !success {
			return fmt.Errorf("Cannot verify a signature against the given authenticated users")
		}
	}
	return nil
}
