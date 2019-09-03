package verify

/*
Struct holds the messages that will be sent around in the protocol. You have
to define each message twice: once the actual message, and a second time
with the `*onet.TreeNode` embedded. The latter is used in the handler-function
so that it can find out who sent the message.
*/
import (
	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3"
)

// Name can be used from other packages to refer to this protocol.
const Name = "VerifyExecutionRequest"

var suite = pairing.NewSuiteBn256()

//type VerifyExecPlan func(vs *Verify) bool

type Verify struct {
	Index       int
	TxnName     string
	Block       *skipchain.SkipBlock
	ExecPlan    *sys.ExecutionPlan
	ClientSigs  map[string][]byte
	CompilerSig protocol.BlsSignature
	UnitSigs    []protocol.BlsSignature
}

type ProtoVerify struct {
	*onet.TreeNode
	Verify
}

type VerifyReply struct {
	Success bool
}

type ProtoVerifyReply struct {
	*onet.TreeNode
	VerifyReply
}
