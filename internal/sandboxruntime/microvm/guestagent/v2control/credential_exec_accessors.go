package v2control

func (environment ExecEnvironment) Name() string                  { return environment.state.name }
func (environment ExecEnvironment) Source() ExecEnvironmentSource { return environment.state.source }
func (environment ExecEnvironment) Value() string                 { return environment.state.value }
func (timing ExecTiming) Kind() ExecTimingKind                    { return timing.state.kind }
func (timing ExecTiming) Value() int64                            { return timing.state.value }

func (plan ExecPlan) Args() []string {
	if plan.state == nil {
		return nil
	}
	return append([]string(nil), plan.state.args...)
}

func (plan ExecPlan) Environment() []ExecEnvironment {
	if plan.state == nil {
		return nil
	}
	return cloneExecEnvironment(plan.state.environment)
}

func (plan ExecPlan) WorkDirectory() string {
	if plan.state == nil {
		return ""
	}
	return plan.state.workDirectory
}

func (plan ExecPlan) StdinMaxBytes() uint32 {
	if plan.state == nil {
		return 0
	}
	return plan.state.stdinMaxBytes
}

func (plan ExecPlan) StdoutMaxBytes() uint32 {
	if plan.state == nil {
		return 0
	}
	return plan.state.stdoutMaxBytes
}

func (plan ExecPlan) StderrMaxBytes() uint32 {
	if plan.state == nil {
		return 0
	}
	return plan.state.stderrMaxBytes
}

func (plan ExecPlan) Timing() ExecTiming {
	if plan.state == nil {
		return ExecTiming{}
	}
	return plan.state.timing
}

func (request CredentialExecRequest) RequestID() RequestID {
	if request.state == nil {
		return RequestID{}
	}
	return request.state.requestID
}

func (request CredentialExecRequest) IdentityDigest() IdentityDigest {
	if request.state == nil {
		return IdentityDigest{}
	}
	return request.state.identityDigest
}

func (request CredentialExecRequest) Identity() JobIdentity {
	if request.state == nil {
		return JobIdentity{}
	}
	return cloneJobIdentity(request.state.identity)
}

func (request CredentialExecRequest) Revision() uint64 {
	if request.state == nil {
		return 0
	}
	return request.state.revision
}

func (request CredentialExecRequest) ExecBindingID() string {
	if request.state == nil {
		return ""
	}
	return request.state.execBindingID
}

func (request CredentialExecRequest) Plan() ExecPlan {
	if request.state == nil {
		return ExecPlan{}
	}
	return cloneExecPlan(request.state.plan)
}

func (request CredentialExecRequest) PrivateRecordCount() uint32 {
	if request.state == nil {
		return 0
	}
	return request.state.privateRecordCount
}

func (request CredentialExecRequest) PrivateAggregateBytes() uint64 {
	if request.state == nil {
		return 0
	}
	return request.state.privateAggregateBytes
}

func (request CredentialExecRequest) PrivateAggregateSHA256() string {
	if request.state == nil {
		return ""
	}
	return request.state.privateAggregateSHA256
}

func (response CredentialExecSuccessResponse) RequestID() RequestID {
	if response.state == nil {
		return RequestID{}
	}
	return response.state.requestID
}

func (response CredentialExecSuccessResponse) IdentityDigest() IdentityDigest {
	if response.state == nil {
		return IdentityDigest{}
	}
	return response.state.identityDigest
}

func (response CredentialExecSuccessResponse) Revision() uint64 {
	if response.state == nil {
		return 0
	}
	return response.state.revision
}

func (response CredentialExecSuccessResponse) ExitCode() int32 {
	if response.state == nil {
		return 0
	}
	return response.state.exitCode
}

func (response CredentialExecSuccessResponse) StdinBytes() uint64 {
	if response.state == nil {
		return 0
	}
	return response.state.stdinBytes
}

func (response CredentialExecSuccessResponse) StdinSHA256() string {
	if response.state == nil {
		return ""
	}
	return response.state.stdinSHA256
}

func (response CredentialExecSuccessResponse) StdoutBytes() uint64 {
	if response.state == nil {
		return 0
	}
	return response.state.stdoutBytes
}

func (response CredentialExecSuccessResponse) StdoutSHA256() string {
	if response.state == nil {
		return ""
	}
	return response.state.stdoutSHA256
}

func (response CredentialExecSuccessResponse) StdoutTruncated() bool {
	return response.state != nil && response.state.stdoutTruncated
}

func (response CredentialExecSuccessResponse) StderrBytes() uint64 {
	if response.state == nil {
		return 0
	}
	return response.state.stderrBytes
}

func (response CredentialExecSuccessResponse) StderrSHA256() string {
	if response.state == nil {
		return ""
	}
	return response.state.stderrSHA256
}

func (response CredentialExecSuccessResponse) StderrTruncated() bool {
	return response.state != nil && response.state.stderrTruncated
}

func (response CredentialExecSuccessResponse) ExecTransactionSHA256() string {
	if response.state == nil {
		return ""
	}
	return response.state.execTransactionSHA256
}
