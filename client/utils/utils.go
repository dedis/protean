package utils

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/dedis/protean/sys"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

//func PrepareWorkflow(wFilePtr *string, dirInfo []*sys.UnitInfo) ([]*sys.WfNode, error) {
func PrepareWorkflow(wFilePtr *string, dirInfo map[string]*sys.UnitInfo) ([]*sys.WfNode, error) {
	var tmpWf []sys.WfJSON
	fh, err := os.Open(*wFilePtr)
	if err != nil {
		log.Errorf("Cannot open file %s: %v", *wFilePtr, err)
		return nil, err
	}
	defer fh.Close()
	buf, err := ioutil.ReadAll(fh)
	if err != nil {
		log.Errorf("Error reading file %s: %v", *wFilePtr, err)
		return nil, err
	}
	err = json.Unmarshal(buf, &tmpWf)
	if err != nil {
		log.Errorf("Cannot unmarshal json value: %v", err)
		return nil, err
	}
	sz := len(tmpWf)
	wf := make([]*sys.WfNode, sz)
	for i := 0; i < sz; i++ {
		tmp := tmpWf[i]
		//for _, u := range dirInfo {
		//if strings.Compare(tmp.UnitName, u.UnitName) == 0 {
		//wf[i] = &sys.WfNode{
		//UID:  u.UnitID,
		//TID:  u.Txns[tmp.TxnName],
		//Deps: tmp.Deps,
		//}
		//}
		//}
		unitInfo, ok := dirInfo[tmp.UnitName]
		if ok {
			wf[i] = &sys.WfNode{
				UID:  unitInfo.UnitID,
				TID:  unitInfo.Txns[tmp.TxnName],
				Deps: tmp.Deps,
			}
		}
	}
	return wf, nil
}

func Setup(roster *onet.Roster, uFilePtr *string, tFilePtr *string) ([]byte, map[string]string, map[string]string, error) {
	return nil, nil, nil, nil
}

func PrepareUnits(roster *onet.Roster, uFilePtr *string, tFilePtr *string) ([]*sys.FunctionalUnit, error) {
	var units []*sys.FunctionalUnit
	file, err := os.Open(*uFilePtr)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	fs := bufio.NewScanner(file)
	for fs.Scan() {
		line := fs.Text()
		tokens := strings.Split(line, ",")
		uType, err := strconv.Atoi(tokens[0])
		if err != nil {
			log.Errorf("Cannot convert unit type: %v", err)
			return nil, err
		}
		numNodes, err := strconv.Atoi(tokens[2])
		if err != nil {
			log.Errorf("Cannot convert num nodes: %v", err)
			return nil, err
		}
		if err != nil {
			log.Errorf("Cannot convert num faulty: %v", err)
			return nil, err
		}
		fu := &sys.FunctionalUnit{
			Type:     uType,
			Name:     tokens[1],
			Roster:   roster,
			Publics:  roster.Publics(),
			NumNodes: numNodes,
		}
		units = append(units, fu)
	}
	file.Close()
	file, err = os.Open(*tFilePtr)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	fs = bufio.NewScanner(file)
	for fs.Scan() {
		line := fs.Text()
		tokens := strings.Split(line, ",")
		uIdx, err := strconv.Atoi(tokens[0])
		if err != nil {
			log.Errorf("Cannot convert unit type: %v", err)
			return nil, err
		}
		units[uIdx].Txns = append(units[uIdx].Txns, tokens[1])
	}
	return units, nil
}
