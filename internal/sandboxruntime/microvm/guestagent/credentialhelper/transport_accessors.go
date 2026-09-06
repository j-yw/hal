package credentialhelper

import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"

func (value ReceivedBootstrap) AgentIdentitySHA256() [32]byte { return value.agentIdentitySHA256 }
func (value ReceivedBootstrap) BootGeneration() credentialprotocol.SafeID {
	return value.bootGeneration
}
func (value ReceivedBootstrap) HelperGeneration() credentialprotocol.SafeID {
	return value.helperGeneration
}

func (value ReceivedAgentHello) BootstrapSHA256() [32]byte { return value.bootstrapSHA256 }
func (value ReceivedAgentHello) BootGeneration() credentialprotocol.SafeID {
	return value.bootGeneration
}
func (value ReceivedAgentHello) HelperGeneration() credentialprotocol.SafeID {
	return value.helperGeneration
}
func (value ReceivedAgentHello) ProcessDescriptorSHA256() [32]byte {
	return value.processDescriptorSHA256
}

func (value ReceivedPrepareBegin) Revision() uint64                  { return value.revision }
func (value ReceivedPrepareBegin) ExpiryUnixNano() int64             { return value.expiryUnixNano }
func (value ReceivedPrepareBegin) Manifest() ManifestCapability      { return value.manifest }
func (value ReceivedPrepareFile) Revision() uint64                   { return value.revision }
func (value ReceivedPrepareFile) BindingIndex() uint16               { return value.bindingIndex }
func (value ReceivedPrepareFile) FileLength() uint32                 { return value.fileLength }
func (value ReceivedPrepareFile) FileSHA256() [32]byte               { return value.fileSHA256 }
func (value ReceivedPrepareCommit) Revision() uint64                 { return value.revision }
func (value ReceivedPrepareCommit) ManifestSHA256() [32]byte         { return value.manifestSHA256 }
func (value ReceivedRenew) Revision() uint64                         { return value.revision }
func (value ReceivedRenew) ExpiryUnixNano() int64                    { return value.expiryUnixNano }
func (value ReceivedRenew) PriorProofSHA256() [32]byte               { return value.priorProofSHA256 }
func (value ReceivedRevoke) Revision() uint64                        { return value.revision }
func (value ReceivedRevoke) Reason() credentialprotocol.RevokeReason { return value.reason }
func (value ReceivedExec) Revision() uint64                          { return value.revision }
func (value ReceivedExec) ExecBindingID() credentialprotocol.SafeID  { return value.execBindingID }
func (value ReceivedExec) PrivateBindingLength() uint32              { return value.privateLength }
func (value ReceivedExec) PrivateBindingSHA256() [32]byte            { return value.privateSHA256 }
func (value ReceivedExec) Plan() ExecPlanCapability                  { return value.plan }
func (value ReceivedExecPrivate) Revision() uint64                   { return value.revision }
func (value ReceivedExecPrivate) PrivateBindingLength() uint32       { return value.privateBindingLength }
func (value ReceivedExecPrivate) PrivateBindingSHA256() [32]byte     { return value.privateBindingSHA256 }
func (value ReceivedExecStream) Revision() uint64                    { return value.revision }
func (value ReceivedExecStream) StreamKind() credentialprotocol.HelperExecStreamKind {
	return value.streamKind
}
func (value ReceivedExecStream) Flags() credentialprotocol.HelperExecStreamFlags { return value.flags }
func (value ReceivedExecStream) Offset() uint64                                  { return value.offset }
func (value ReceivedExecStream) PayloadLength() uint32                           { return value.payloadLength }
func (value ReceivedExecStream) PayloadSHA256() [32]byte                         { return value.payloadSHA256 }
func (value ReceivedExecCredit) Revision() uint64                                { return value.revision }
func (value ReceivedExecCredit) StreamKind() credentialprotocol.HelperExecStreamKind {
	return value.streamKind
}
func (value ReceivedExecCredit) NextOffset() uint64                      { return value.nextOffset }
func (value ReceivedCloseNotify) Reason() credentialprotocol.CloseReason { return value.reason }

func (packet ReceivedPacket) Bootstrap() (ReceivedBootstrap, bool) {
	value, ok := packet.arm.(ReceivedBootstrap)
	return value, ok
}
func (packet ReceivedPacket) AgentHello() (ReceivedAgentHello, bool) {
	value, ok := packet.arm.(ReceivedAgentHello)
	return value, ok
}
func (packet ReceivedPacket) PrepareBegin() (ReceivedPrepareBegin, bool) {
	value, ok := packet.arm.(ReceivedPrepareBegin)
	return value, ok
}
func (packet ReceivedPacket) PrepareFile() (ReceivedPrepareFile, bool) {
	value, ok := packet.arm.(ReceivedPrepareFile)
	return value, ok
}
func (packet ReceivedPacket) PrepareCommit() (ReceivedPrepareCommit, bool) {
	value, ok := packet.arm.(ReceivedPrepareCommit)
	return value, ok
}
func (packet ReceivedPacket) Renew() (ReceivedRenew, bool) {
	value, ok := packet.arm.(ReceivedRenew)
	return value, ok
}
func (packet ReceivedPacket) Revoke() (ReceivedRevoke, bool) {
	value, ok := packet.arm.(ReceivedRevoke)
	return value, ok
}
func (packet ReceivedPacket) Exec() (ReceivedExec, bool) {
	value, ok := packet.arm.(ReceivedExec)
	return value, ok
}
func (packet ReceivedPacket) ExecPrivate() (ReceivedExecPrivate, bool) {
	value, ok := packet.arm.(ReceivedExecPrivate)
	return value, ok
}
func (packet ReceivedPacket) ExecStream() (ReceivedExecStream, bool) {
	value, ok := packet.arm.(ReceivedExecStream)
	return value, ok
}
func (packet ReceivedPacket) ExecCredit() (ReceivedExecCredit, bool) {
	value, ok := packet.arm.(ReceivedExecCredit)
	return value, ok
}
func (packet ReceivedPacket) CloseNotify() (ReceivedCloseNotify, bool) {
	value, ok := packet.arm.(ReceivedCloseNotify)
	return value, ok
}
