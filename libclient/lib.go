package libclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/dedis/protean/core"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"io/ioutil"
	"os"
)

//func GetTransaction(contract *Contract, wfName string, txnName string) (*Transaction, error) {
//	if wf, ok := contract.Workflows[wfName]; ok {
//		if txn, ok := wf.Txns[txnName]; ok {
//			size := len(txn.Opcodes)
//			opcodes := make([]*Opcode, size)
//			for i, op := range txn.Opcodes {
//				opcodes[i] = &Opcode{
//					Name:  op.Name,
//					DFUID: op.DFUID,
//				}
//				if op.Dependencies != nil {
//					deps := make(map[string]*DataDependency)
//					for paramName, inputObj := range op.Dependencies {
//						dataDep := &DataDependency{}
//						switch inputObj.Src {
//						case CONST:
//							dataDep.Dep = ConstDependency{
//								Value: inputObj.Value,
//							}
//						case KEYVALUE:
//							kvDep := &KVDependency{}
//							err := getKVDependency(kvDep, inputObj.Value)
//							if err != nil {
//								return nil, fmt.Errorf("error creating kv dependencies: %v", err)
//							}
//							dataDep.Dep = kvDep
//						case OPCODE:
//							dataDep.Dep = &OpcodeDependency{
//								SrcName:   inputObj.SrcName,
//								OpcodeIdx: inputObj.Idx,
//							}
//						}
//						deps[paramName] = dataDep
//					}
//					opcodes[i].Deps = deps
//				}
//			}
//			return &Transaction{
//				Name:    txnName,
//				Opcodes: opcodes,
//			}, nil
//		} else {
//			return nil, fmt.Errorf("transaction: %s does not exist", txnName)
//		}
//	} else {
//		return nil, fmt.Errorf("workflow: %s does not exist", wfName)
//	}
//}

func ReadContractJSON(file *string) (*core.Contract, error) {
	var contract core.Contract
	fd, err := os.Open(*file)
	if err != nil {
		return nil, xerrors.Errorf("Cannot open file: %v", err)
	}
	defer fd.Close()
	buf, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, xerrors.Errorf("Error reading file: %v", err)
	}
	err = json.Unmarshal(buf, &contract)
	if err != nil {
		return nil, xerrors.Errorf("Cannot unmarshal json value: %v", err)
	}
	muxDependencyValue(&contract)
	err = verifyDag(&contract)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return &contract, nil
}

func ReadFSMJSON(file *string) (*core.FSM, error) {
	var fsm core.FSM
	fd, err := os.Open(*file)
	if err != nil {
		return nil, xerrors.Errorf("Cannot open file: %v", err)
	}
	defer fd.Close()
	buf, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, xerrors.Errorf("Error reading file: %v", err)
	}
	err = json.Unmarshal(buf, &fsm)
	if err != nil {
		return nil, xerrors.Errorf("Cannot unmarshal json value: %v", err)
	}
	return &fsm, nil
}

// ReadDFUJSON reads the DFU information into a struct.
// IMPORTANT: JSON file does not contain the public keys so they should be
// added manually before sending the information to the registry
func ReadDFUJSON(file *string) (*core.DFURegistry, error) {
	var dfus core.DFURegistry
	fd, err := os.Open(*file)
	if err != nil {
		return nil, xerrors.Errorf("Cannot open file: %v", err)
	}
	defer fd.Close()
	buf, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, xerrors.Errorf("Error reading file: %v", err)
	}
	err = json.Unmarshal(buf, &dfus)
	if err != nil {
		return nil, xerrors.Errorf("Cannot unmarshal json value: %v", err)
	}
	return &dfus, nil
}

func StoreDependencyValue(c *core.Contract, wf string, txn string, input string,
	idx int, value string, file string) error {
	src := c.Workflows[wf].Txns[txn].Opcodes[idx].Dependencies[input].Src
	if src != core.CONST && src != core.KEYVALUE {
		return xerrors.Errorf("wrong dependency type: expected const")
	}
	c.Workflows[wf].Txns[txn].Opcodes[idx].Dependencies[input].Value = value
	fmt.Println(c.Workflows[wf].Txns[txn].Opcodes[idx].Dependencies)
	content, err := json.Marshal(c)
	if err != nil {
		return xerrors.Errorf("json marshal error: %v", err)
	}
	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, content, "", "\t")
	if err != nil {
		return xerrors.Errorf("json indent error: %v", err)
	}
	err = ioutil.WriteFile(file, prettyJSON.Bytes(), 0644)
	return err
}

func muxDependencyValue(contract *core.Contract) {
	for _, wf := range contract.Workflows {
		for _, txn := range wf.Txns {
			for _, opcode := range txn.Opcodes {
				for _, dep := range opcode.Dependencies {
					switch v := dep.Value.(type) {
					case float64:
						dep.UintValue = uint64(v)
					case string:
						dep.StringValue = v
					default:
					}
					dep.Value = nil
				}
			}
		}
	}
}

type edge struct {
	parent  int
	child   int
	removed bool
}

func verifyDag(contract *core.Contract) error {
	for wfName, wf := range contract.Workflows {
		for txnName, txn := range wf.Txns {
			var edges []*edge
			nodes := make(map[int]bool)
			for idx, opcode := range txn.Opcodes {
				nodes[idx] = true
				for _, dep := range opcode.Dependencies {
					if dep.Src == core.OPCODE {
						edges = append(edges, &edge{parent: dep.Idx,
							child: idx, removed: false})
					}
				}
			}
			var sorted []int
			idx := 0
			noIncoming := findNoIncoming(nodes, edges)
			for idx < len(noIncoming) {
				curr := noIncoming[idx]
				sorted = append(sorted, curr)
				for i := 0; i < len(edges); i++ {
					tmp := edges[i]
					if curr == tmp.parent && tmp.removed == false {
						tmp.removed = true
						if !hasIncomingEdge(tmp.child, edges) {
							noIncoming = append(noIncoming, tmp.child)
						}
					}
				}
				idx++
			}
			for _, edge := range edges {
				if edge.removed == false {
					return xerrors.Errorf("%s:%s has circular dependency",
						wfName, txnName)
				}
			}
		}
	}
	return nil
}

func hasIncomingEdge(node int, edges []*edge) bool {
	for _, edge := range edges {
		if (node == edge.child) && (edge.removed == false) {
			return true
		}
	}
	return false
}

func findNoIncoming(nodes map[int]bool, edges []*edge) []int {
	var noIncoming []int
	for _, edge := range edges {
		nodes[edge.child] = false
	}
	for k, v := range nodes {
		if v == true {
			noIncoming = append(noIncoming, k)
		}
	}
	return noIncoming
}
