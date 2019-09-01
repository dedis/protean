package sys

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

//TODO: Curently there is a single roster and every unit uses the same roster.
//Each line in the units.txt file should specify the number of nodes in that
//unit. Then we can parse a single roster file, using the node count information
//to determine where a new roster starts. (Potentially use onet.NewRoster)
//func PrepareUnits(roster *onet.Roster, uFilePtr *string, tFilePtr *string) ([]*FunctionalUnit, error) {
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
		fmt.Println("In PrepareUnits publics size is:", len(units[i].Publics))
		//TODO: Revert to ServicePublics() once you have the suitable
		//roster.toml file generated
		//sn := fus[i].Name + "Service"
		//fus[i].Publics = roster.ServicePublics(sn)
		//units[i] = &fus[i]
	}
	return units, nil
}
