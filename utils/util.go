package utils

import (
	"bufio"
	"fmt"
	"github.com/ceyhunalp/protean_code/compiler"
	"go.dedis.ch/cothority/v3"
	//"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/log"
	"os"
	"strconv"
	"strings"
)

func CreateWorkflow(wfFilePtr *string, uData map[string]string, tData map[string]string) ([]*compiler.WfNode, error) {
	var wf []*compiler.WfNode
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
		wf = append(wf, &compiler.WfNode{
			Index: idx,
			UId:   uData[tokens[1]],
			TId:   tData[tokens[2]],
			Deps:  deps})
		idx++
	}
	return wf, nil
}

//func PrepareUnits(roster *onet.Roster, uFilePtr *string, tFilePtr *string) (*compiler.CreateUnitsRequest, error) {
func PrepareUnits(roster *onet.Roster, uFilePtr *string, tFilePtr *string) ([]*compiler.FunctionalUnit, error) {
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
			UnitType:   uType,
			UnitName:   tokens[1],
			Roster:     roster,
			PublicKeys: roster.Publics(),
			NumNodes:   numNodes,
			NumFaulty:  numFaulty,
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
		//txn := &compiler.Transaction{
		//TxnName: tokens[1],
		//}
		//units[uIdx].Txns = append(units[uIdx].Txns, txn)
		units[uIdx].Txns = append(units[uIdx].Txns, tokens[1])
	}
	return units, nil
	//return &compiler.CreateUnitsRequest{Units: units}, nil
}

//func Setup(roster *onet.Roster, uFilePtr *string, tFilePtr *string) (map[string]string, map[string]string, error) {
func Setup(roster *onet.Roster, uFilePtr *string, tFilePtr *string) ([]byte, map[string]string, map[string]string, error) {
	//req, err := PrepareUnits(roster, uFilePtr, tFilePtr)
	units, err := PrepareUnits(roster, uFilePtr, tFilePtr)
	if err != nil {
		return nil, nil, nil, err
	}
	cl := compiler.NewClient()
	defer cl.Close()
	csReply, err := cl.CreateSkipchain(roster, 2, 2)
	if err != nil {
		return nil, nil, nil, err
	}
	//req.Genesis = csReply.Genesis
	//reply, err := cl.CreateUnits(roster, req)
	reply, err := cl.CreateUnits(roster, csReply.Genesis, units)
	if err != nil {
		return nil, nil, nil, err
	}

	uMap, tMap := generateDirectoryData(reply)
	//uMap, tMap := generateDirectoryData(req, reply)
	return csReply.Genesis, uMap, tMap, nil
}

func GetServerKey(fname *string) (kyber.Point, error) {
	var keys []kyber.Point
	fh, err := os.Open(*fname)
	defer fh.Close()
	if err != nil {
		log.Errorf("GetServerKey error: %v", err)
		return nil, err
	}

	fs := bufio.NewScanner(fh)
	for fs.Scan() {
		tmp, err := encoding.StringHexToPoint(cothority.Suite, fs.Text())
		if err != nil {
			log.Errorf("GetServerKey error: %v", err)
			return nil, err
		}
		keys = append(keys, tmp)
	}
	return keys[0], nil
}

func ReadRoster(path *string) (*onet.Roster, error) {
	file, err := os.Open(*path)
	if err != nil {
		log.Errorf("ReadRoster error: %v", err)
		return nil, err
	}

	group, err := app.ReadGroupDescToml(file)
	if err != nil {
		log.Errorf("ReadRoster error: %v", err)
		return nil, err
	}

	if len(group.Roster.List) == 0 {
		fmt.Println("Empty roster")
		log.Errorf("ReadRoster error: %v", err)
		return nil, err
	}
	return group.Roster, nil
}

func generateDirectoryData(reply *compiler.CreateUnitsReply) (map[string]string, map[string]string) {
	// Unit name -> uid
	// Txn name  -> tid
	unitMap := make(map[string]string)
	txnMap := make(map[string]string)
	for i := 0; i < len(reply.Data); i++ {
		fmt.Println("In utils:", reply.Data[i].UnitName, reply.Data[i].UnitId)
		unitMap[reply.Data[i].UnitName] = reply.Data[i].UnitId
		for k, v := range reply.Data[i].Txns {
			txnMap[v] = k
		}

	}
	return unitMap, txnMap
}
