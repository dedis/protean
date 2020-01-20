package utils

// TODO: For now we only ask the clients to sign the execution plan. However,
// note that the fields of an execution plan do not change over the course of
// its execution. In the case of requiring signatures from all authorized users
// to execute a workflow, it might be a good idea to produce a signature for
// each call that corresponds to a txn in the workflow. One option is to
// Sign(Index || EP) instead of Sign(EP).
//func SignWorkflow(wf *sys.Workflow, sk kyber.Scalar) ([]byte, error) {
//wfHash, err := utils.ComputeWFHash(wf)
//if err != nil {
//log.Errorf("Cannot compute the hash of workflow: %v", err)
//return nil, err
//}
//sig, err := schnorr.Sign(cothority.Suite, sk, wfHash)
//if err != nil {
//log.Errorf("Cannot sign the workflow: %v", err)
//}
//return sig, err
//}

//func SignExecutionPlan(idx int, ep *sys.ExecutionPlan, sk kyber.Scalar) ([]byte, error) {
//epHash, err := utils.ComputeEPHash(ep)
//if err != nil {
//log.Errorf("Cannot compute the hash of the execution plan: %v", err)
//return nil, err
//}
//data := append([]byte(strconv.Itoa(idx)), epHash...)
//sig, err := schnorr.Sign(cothority.Suite, sk, data)
//if err != nil {
//log.Errorf("Cannot sign the execution plan: %v", err)
//}
//return sig, err
//}
