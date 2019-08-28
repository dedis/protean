package utils

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/dedis/protean"
	"github.com/dedis/protean/sys"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func CreateWorkflow(wfFilePtr *string, uData map[string]string, tData map[string]string) ([]*protean.WfNode, error) {
	var wf []*protean.WfNode
	file, err := os.Open(*wfFilePtr)
	defer file.Close()
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	idx := 0
	fs := bufio.NewScanner(file)
	for fs.Scan() {
		var deps []int
		line := fs.Text()
		tokens := strings.Split(line, ":")
		if tokens[3] != "" {
			depStr := strings.Split(tokens[3], ",")
			for _, d := range depStr {
				dep, err := strconv.Atoi(d)
				if err != nil {
					log.Errorf("CreateWorkflow error:%v", err)
					return nil, err
				}
				deps = append(deps, dep)
			}
		}
		wf = append(wf, &protean.WfNode{
			//Index: idx,
			UID:  uData[tokens[1]],
			TID:  tData[tokens[2]],
			Deps: deps})
		idx++
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
