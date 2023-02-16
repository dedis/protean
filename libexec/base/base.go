package base

const (
	UID  string = "codeexec"
	EXEC string = "exec"
)

type ExecutionFn func(input *GenericInput) (*GenericOutput, error)

type ExecuteInput struct {
	Data []byte
}

type ExecuteOutput struct {
	Data []byte
}

type GenericInput struct {
	I interface{}
}

type GenericOutput struct {
	O interface{}
}
