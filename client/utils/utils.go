package utils

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func PrepareWorkflow(wFilePtr *string, dirInfo map[string]*sys.UnitInfo, publics []kyber.Point, all bool) (*sys.Workflow, error) {
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
	wfNodes := make([]*sys.WfNode, sz)
	for i := 0; i < sz; i++ {
		tmp := tmpWf[i]
		unitInfo, ok := dirInfo[tmp.UnitName]
		if ok {
			wfNodes[i] = &sys.WfNode{
				UID:  unitInfo.UnitID,
				TID:  unitInfo.Txns[tmp.TxnName],
				Deps: tmp.Deps,
			}
		}
	}

	var authPublics map[string]kyber.Point
	if publics != nil {
		authPublics = make(map[string]kyber.Point)
		for _, pk := range publics {
			authPublics[pk.String()] = pk
		}
	}
	return &sys.Workflow{Nodes: wfNodes, AuthPublics: authPublics, All: all}, nil
}

// TODO: For now we only ask the clients to sign the execution plan. However,
// note that the fields of an execution plan do not change over the course of
// its execution. In the case of requiring signatures from all authorized users
// to execute a workflow, it might be a good idea to produce a signature for
// each call that corresponds to a txn in the workflow. One option is to
// Sign(Index || EP) instead of Sign(EP).
func SignExecutionPlan(ep *sys.ExecutionPlan, sk kyber.Scalar) ([]byte, error) {
	epHash, err := utils.ComputeEPHash(ep)
	if err != nil {
		log.Errorf("Cannot compute the hash of the execution plan: %v", err)
		return nil, err
	}
	sig, err := schnorr.Sign(cothority.Suite, sk, epHash)
	if err != nil {
		log.Errorf("Cannot sign the workflow: %v", err)
	}
	return sig, err
}

//TODO: Delete Setup and PrepareUnits

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
