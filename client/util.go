package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/dedis/protean"
	"github.com/dedis/protean/compiler"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func createWorkflow(wfFilePtr *string, uData map[string]string, tData map[string]string) ([]*protean.WfNode, error) {
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

func generateDirectoryData(reply *compiler.CreateUnitsReply) (map[string]string, map[string]string) {
	// Unit name -> uid
	// Txn name  -> tid
	unitMap := make(map[string]string)
	txnMap := make(map[string]string)
	for i := 0; i < len(reply.UnitDirectory); i++ {
		fmt.Println("In utils:", reply.UnitDirectory[i].UnitName, reply.UnitDirectory[i].UnitID)
		unitMap[reply.UnitDirectory[i].UnitName] = reply.UnitDirectory[i].UnitID
		for k, v := range reply.UnitDirectory[i].Txns {
			txnMap[v] = k
		}

	}
	return unitMap, txnMap
}

func setup(roster *onet.Roster, uFilePtr *string, tFilePtr *string) ([]byte, map[string]string, map[string]string, error) {
	units, err := prepareUnits(roster, uFilePtr, tFilePtr)
	if err != nil {
		return nil, nil, nil, err
	}
	cl := compiler.NewClient(roster)
	defer cl.Close()
	iuReply, err := cl.InitUnit(&protean.ScInitData{Roster: roster, MHeight: 2, BHeight: 2})
	if err != nil {
		return nil, nil, nil, err
	}
	reply, err := cl.CreateUnits(iuReply.Genesis, units)
	if err != nil {
		return nil, nil, nil, err
	}

	uMap, tMap := generateDirectoryData(reply)
	return iuReply.Genesis, uMap, tMap, nil
}

func prepareUnits(roster *onet.Roster, uFilePtr *string, tFilePtr *string) ([]*compiler.FunctionalUnit, error) {
	var units []*compiler.FunctionalUnit
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
		numFaulty, err := strconv.Atoi(tokens[3])
		if err != nil {
			log.Errorf("Cannot convert num faulty: %v", err)
			return nil, err
		}
		fu := &compiler.FunctionalUnit{
			UnitType:  uType,
			UnitName:  tokens[1],
			Roster:    roster,
			Publics:   roster.Publics(),
			NumNodes:  numNodes,
			NumFaulty: numFaulty,
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
