package sandboxworker

func (service *L8Service) jobStatusV2Response(requestID, principalID string, request JobStatusRequestV2) Response {
	if err := request.Validate(); err != nil {
		return protocolErrorResponse(requestID, OperationJobStatusV2, ErrorCodeMalformedRequest, "malformed worker v2 job status request")
	}
	job, err := service.jobs.status(request.JobID, principalID)
	if err != nil {
		return protocolErrorResponse(requestID, OperationJobStatusV2, ErrorCodeJobNotFound, "worker v2 job was not found")
	}
	return Response{RequestID: requestID, Operation: OperationJobStatusV2, OK: true, JobV2: &job}
}
