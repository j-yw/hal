package sandboxworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func readWorkerJSONBoundedV2(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("worker JSON limit is invalid")
	}
	limited := &io.LimitedReader{R: reader, N: maxBytes}
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if limited.N == 0 {
		var probe [1]byte
		n, probeErr := io.ReadFull(reader, probe[:])
		if n > 0 {
			return nil, errors.New("worker JSON exceeds limit")
		}
		if n == 0 && probeErr == io.EOF {
			return raw, nil
		}
		if probeErr != nil {
			return nil, probeErr
		}
		return nil, errors.New("worker JSON probe made no progress")
	}
	return raw, nil
}

func decodeWorkerRequestInto(reader io.Reader, maxBytes int64, output *Request) error {
	raw, err := readWorkerJSONBoundedV2(reader, maxBytes)
	if err != nil {
		return err
	}
	if err := validateWorkerJSONPreflightV2(string(raw)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func decodeWorkerResponseInto(reader io.Reader, maxBytes int64, output *Response) error {
	raw, err := readWorkerJSONBoundedV2(reader, maxBytes)
	if err != nil {
		return err
	}
	if err := validateWorkerJSONPreflightV2(string(raw)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func decodeStoredJobStateV2Into(reader io.Reader, maxBytes int64, output *storedJobStateV2) error {
	raw, err := readWorkerJSONBoundedV2(reader, maxBytes)
	if err != nil {
		return err
	}
	if err := validateWorkerJSONPreflightV2(string(raw)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func decodeWorkerResponse(reader io.Reader) (Response, error) {
	var output Response
	if err := decodeWorkerResponseInto(reader, defaultMaxResponseBytes, &output); err != nil {
		return Response{}, err
	}
	return output, nil
}

func encodeWorkerResponse(writer io.Writer, response Response) error {
	encoder := json.NewEncoder(writer)
	return encoder.Encode(response)
}

func validateWorkerJSONPreflightV2(raw string) error {
	if !utf8.ValidString(raw) {
		return errors.New("worker JSON text is invalid")
	}
	parser := workerJSONPreflightV2{raw: raw}
	if err := parser.parseValue(workerJSONPreflightRootV2); err != nil {
		return err
	}
	parser.skipSpace()
	if parser.offset != len(parser.raw) {
		return errors.New("worker JSON has trailing data")
	}
	return nil
}

const workerJSONPreflightMaxDepthV2 = 10_000

type workerJSONPreflightContextV2 uint8

const (
	workerJSONPreflightGenericV2 workerJSONPreflightContextV2 = iota
	workerJSONPreflightTypedObjectV2
	workerJSONPreflightStringMapV2
	workerJSONPreflightRootV2
	workerJSONPreflightJobV2
	workerJSONPreflightProductionFlagV2
)

// workerJSONPreflightCanonicalTagsV2 is the audited union of JSON tags reachable
// from worker requests, responses, and private V2 job state. The root-only
// jobV2/JobV2 fold collision is classified separately after the root is read.
var workerJSONPreflightCanonicalTagsV2 = map[string]string{
	"action":                         "action",
	"activationgeneration":           "activationGeneration",
	"activationid":                   "activationId",
	"activemodes":                    "activeModes",
	"activeproofs":                   "activeProofs",
	"activesandboxes":                "activeSandboxes",
	"adapterid":                      "adapterId",
	"admissiongrantid":               "admissionGrantId",
	"admissiongrantrevision":         "admissionGrantRevision",
	"algorithm":                      "algorithm",
	"apipath":                        "apiPath",
	"args":                           "args",
	"argv":                           "argv",
	"assetrole":                      "assetRole",
	"assets":                         "assets",
	"backend":                        "backend",
	"bindingid":                      "bindingId",
	"bindingids":                     "bindingIds",
	"bindings":                       "bindings",
	"cancelrequested":                "cancelRequested",
	"capabilities":                   "capabilities",
	"capability":                     "capability",
	"capabilitylabels":               "capabilityLabels",
	"capacity":                       "capacity",
	"code":                           "code",
	"contractversion":                "contractVersion",
	"controllerkeygeneration":        "controllerKeyGeneration",
	"copyin":                         "copyIn",
	"copyout":                        "copyOut",
	"create":                         "create",
	"credentialdelivery":             "credentialDelivery",
	"credentialgeneration":           "credentialGeneration",
	"credentialintent":               "credentialIntent",
	"credentialstate":                "credentialState",
	"credentialmodes":                "credentialModes",
	"credentialproxymode":            "credentialProxyMode",
	"cursor":                         "cursor",
	"daemongeneration":               "daemonGeneration",
	"data":                           "data",
	"decision":                       "decision",
	"defaultposture":                 "defaultPosture",
	"deliverymode":                   "deliveryMode",
	"deliverymodes":                  "deliveryModes",
	"destination":                    "destination",
	"digest":                         "digest",
	"digestalgorithm":                "digestAlgorithm",
	"digestvalue":                    "digestValue",
	"displaypath":                    "displayPath",
	"document":                       "document",
	"driver":                         "driver",
	"driverid":                       "driverId",
	"encoding":                       "encoding",
	"enforced":                       "enforced",
	"enforcementmode":                "enforcementMode",
	"env":                            "env",
	"environment":                    "environment",
	"error":                          "error",
	"errorcodes":                     "errorCodes",
	"errorcount":                     "errorCount",
	"exec":                           "exec",
	"executionid":                    "executionId",
	"executablerole":                 "executableRole",
	"exitcode":                       "exitCode",
	"failurecode":                    "failureCode",
	"finishedat":                     "finishedAt",
	"firecrackerprocessgeneration":   "firecrackerProcessGeneration",
	"guestbootgeneration":            "guestBootGeneration",
	"guesthelpergeneration":          "guestHelperGeneration",
	"guestimagedigest":               "guestImageDigest",
	"guestimagegeneration":           "guestImageGeneration",
	"guestsessiongeneration":         "guestSessionGeneration",
	"guestreadiness":                 "guestReadiness",
	"health":                         "health",
	"heartbeatat":                    "heartbeatAt",
	"hostid":                         "hostId",
	"hostkind":                       "hostKind",
	"id":                             "id",
	"image":                          "image",
	"identity":                       "identity",
	"issuedat":                       "issuedAt",
	"inspect":                        "inspect",
	"isolationlevel":                 "isolationLevel",
	"job":                            "job",
	"jobcancel":                      "jobCancel",
	"jobcancelv2":                    "jobCancelV2",
	"jobid":                          "jobId",
	"joblogs":                        "jobLogs",
	"joblogsv2":                      "jobLogsV2",
	"jobresolve":                     "jobResolve",
	"jobresolvev2":                   "jobResolveV2",
	"jobstart":                       "jobStart",
	"jobstartv2":                     "jobStartV2",
	"jobstatus":                      "jobStatus",
	"jobstatusv2":                    "jobStatusV2",
	"labels":                         "labels",
	"lifecycle":                      "lifecycle",
	"limitbytes":                     "limitBytes",
	"limitexceeded":                  "limitExceeded",
	"lockstatus":                     "lockStatus",
	"lockedat":                       "lockedAt",
	"logcursor":                      "logCursor",
	"logtruncated":                   "logTruncated",
	"maxconcurrentsandboxes":         "maxConcurrentSandboxes",
	"maxpayloadbytes":                "maxPayloadBytes",
	"mechanisms":                     "mechanisms",
	"message":                        "message",
	"metadata":                       "metadata",
	"mode":                           "mode",
	"modes":                          "modes",
	"name":                           "name",
	"networkenforcement":             "networkEnforcement",
	"networkenforcementcapability":   "networkEnforcementCapability",
	"networkpolicy":                  "networkPolicy",
	"networkplanid":                  "networkPlanId",
	"nextcursor":                     "nextCursor",
	"ok":                             "ok",
	"oldestcursor":                   "oldestCursor",
	"operation":                      "operation",
	"operationid":                    "operationId",
	"operationplan":                  "operationPlan",
	"operations":                     "operations",
	"orchestration":                  "orchestration",
	"outcome":                        "outcome",
	"pathrole":                       "pathRole",
	"pathroles":                      "pathRoles",
	"payload":                        "payload",
	"payloads":                       "payloads",
	"plan":                           "plan",
	"planid":                         "planId",
	"policypreset":                   "policyPreset",
	"policysnapshotid":               "policySnapshotId",
	"principalid":                    "principalId",
	"processdescriptor":              "processDescriptor",
	"processid":                      "processId",
	"processidsource":                "processIdSource",
	"processlaunch":                  "processLaunch",
	"productioncredentialsrequested": "productionCredentialsRequested",
	"proofid":                        "proofId",
	"protocolversion":                "protocolVersion",
	"provenancelabels":               "provenanceLabels",
	"proxy":                          "proxy",
	"proxygenerationid":              "proxyGenerationId",
	"proxysessionid":                 "proxySessionId",
	"reasoncode":                     "reasonCode",
	"reasoncodes":                    "reasonCodes",
	"records":                        "records",
	"referencekind":                  "referenceKind",
	"remotedestinationpath":          "remoteDestinationPath",
	"remotesourcepath":               "remoteSourcePath",
	"request":                        "request",
	"requestid":                      "requestId",
	"requestkey":                     "requestKey",
	"requested":                      "requested",
	"requestedmodes":                 "requestedModes",
	"result":                         "result",
	"revision":                       "revision",
	"role":                           "role",
	"rulegenerationid":               "ruleGenerationId",
	"rules":                          "rules",
	"runtime":                        "runtime",
	"runtimedriver":                  "runtimeDriver",
	"runtimedrivers":                 "runtimeDrivers",
	"runtimegeneration":              "runtimeGeneration",
	"runtimeid":                      "runtimeId",
	"runtimeimage":                   "runtimeImage",
	"security":                       "security",
	"seed":                           "seed",
	"serviceid":                      "serviceId",
	"sizebytes":                      "sizeBytes",
	"socketpath":                     "socketPath",
	"source":                         "source",
	"sourceartifact":                 "sourceArtifact",
	"sourcekind":                     "sourceKind",
	"sourcereferenceid":              "sourceReferenceId",
	"sourcereferenceids":             "sourceReferenceIds",
	"startedat":                      "startedAt",
	"state":                          "state",
	"status":                         "status",
	"stderr":                         "stderr",
	"stderrlimitbytes":               "stderrLimitBytes",
	"stderrtruncated":                "stderrTruncated",
	"stdin":                          "stdin",
	"stdout":                         "stdout",
	"stdoutlimitbytes":               "stdoutLimitBytes",
	"stdouttruncated":                "stdoutTruncated",
	"stream":                         "stream",
	"submissionid":                   "submissionId",
	"submissionkey":                  "submissionKey",
	"submittedat":                    "submittedAt",
	"supported":                      "supported",
	"supportedoperations":            "supportedOperations",
	"supportedruntimedrivers":        "supportedRuntimeDrivers",
	"supportsdefaultdenyposture":     "supportsDefaultDenyPosture",
	"supportsdomainrules":            "supportsDomainRules",
	"supportsendpointrules":          "supportsEnd" + "pointRules",
	"supportslinklocalrules":         "supportsLinkLocalRules",
	"supportsloopbackrules":          "supportsLoopbackRules",
	"supportsmetadataendpoint":       "supportsMetadataEnd" + "point",
	"supportsprivaterangerules":      "supportsPrivateRangeRules",
	"target":                         "target",
	"templatelock":                   "templateLock",
	"templatepolicyid":               "templatePolicyId",
	"templatereference":              "templateReference",
	"templatestatus":                 "templateStatus",
	"timestamp":                      "timestamp",
	"topologygenerationid":           "topologyGenerationId",
	"transport":                      "transport",
	"truncated":                      "truncated",
	"trustdecision":                  "trustDecision",
	"trustmode":                      "trustMode",
	"trustpolicy":                    "trustPolicy",
	"value":                          "value",
	"vsockgeneration":                "vsockGeneration",
	"warningcodes":                   "warningCodes",
	"warningcount":                   "warningCount",
	"workdir":                        "workDir",
	"workerid":                       "workerId",
	"workerjobid":                    "workerJobId",
	"workspacepolicyid":              "workspacePolicyId",
}

type workerJSONPreflightV2 struct {
	raw                  string
	offset               int
	depth                int
	noncanonicalTypedKey bool
}

func (parser *workerJSONPreflightV2) parseValue(context workerJSONPreflightContextV2) error {
	parser.skipSpace()
	if parser.offset >= len(parser.raw) {
		return errors.New("worker JSON is incomplete")
	}
	requiredProductionFlag := context == workerJSONPreflightProductionFlagV2
	if requiredProductionFlag && parser.raw[parser.offset] != '{' {
		return errors.New("worker JSON credential intent must be an object")
	}
	switch parser.raw[parser.offset] {
	case '{':
		return parser.parseObject(context)
	case '[':
		return parser.parseArray(context)
	case '"':
		_, err := parser.parseString()
		return err
	case 't':
		return parser.parseLiteral("true")
	case 'f':
		return parser.parseLiteral("false")
	case 'n':
		return parser.parseLiteral("null")
	default:
		return parser.parseNumber()
	}
}

func (parser *workerJSONPreflightV2) parseObject(context workerJSONPreflightContextV2) error {
	if err := parser.enterContainer(); err != nil {
		return err
	}
	defer parser.leaveContainer()
	requiredProductionFlag := context == workerJSONPreflightProductionFlagV2
	parser.offset++
	parser.skipSpace()
	seen := make(map[string]bool)
	seenFolded := make(map[string]bool)
	productionFlagSeen := false
	rootTypedDocument := false
	rootEnvelope := false
	rootStoredState := false
	rootJobV2Key := ""
	rootJobV2Token := ""
	if parser.consume('}') {
		if requiredProductionFlag {
			return errors.New("worker JSON productionCredentialsRequested is required")
		}
		return nil
	}
	for {
		parser.skipSpace()
		keyStart := parser.offset
		key, err := parser.parseString()
		if err != nil {
			return err
		}
		keyToken := parser.raw[keyStart:parser.offset]
		if seen[key] {
			return errors.New("worker JSON contains duplicate object key")
		}
		seen[key] = true
		if workerJSONPreflightTypedContextV2(context) {
			folded := workerJSONPreflightFoldKeyV2(key)
			if seenFolded[folded] {
				return errors.New("worker JSON contains duplicate object key")
			}
			seenFolded[folded] = true
			if context == workerJSONPreflightRootV2 && folded == "jobv2" {
				rootJobV2Key = key
				rootJobV2Token = keyToken
			} else if canonical, known := workerJSONPreflightCanonicalTagsV2[folded]; known && (key != canonical || keyToken != `"`+canonical+`"`) {
				parser.noncanonicalTypedKey = true
			}
			if context == workerJSONPreflightRootV2 {
				switch folded {
				case "protocolversion", "requestid", "operation":
					rootTypedDocument = true
					rootEnvelope = true
				case "ok":
					rootTypedDocument = true
					rootEnvelope = true
				case "requestkey", "principalid", "daemongeneration", "credentialstate":
					rootTypedDocument = true
					rootStoredState = true
				}
			}
		}
		parser.skipSpace()
		if !parser.consume(':') {
			return errors.New("worker JSON object separator is invalid")
		}
		parser.skipSpace()
		if requiredProductionFlag && strings.EqualFold(key, "productionCredentialsRequested") {
			if productionFlagSeen {
				return errors.New("worker JSON contains duplicate object key")
			}
			if !strings.HasPrefix(parser.raw[parser.offset:], "true") && !strings.HasPrefix(parser.raw[parser.offset:], "false") {
				return errors.New("worker JSON productionCredentialsRequested must be boolean")
			}
			productionFlagSeen = true
		}
		if err := parser.parseValue(workerJSONPreflightChildContextV2(context, key)); err != nil {
			return err
		}
		parser.skipSpace()
		if parser.consume('}') {
			if requiredProductionFlag && !productionFlagSeen {
				return errors.New("worker JSON productionCredentialsRequested is required")
			}
			if context == workerJSONPreflightRootV2 {
				return parser.validateRootCanonicalKeys(rootTypedDocument, rootEnvelope, rootStoredState, rootJobV2Key, rootJobV2Token)
			}
			return nil
		}
		if !parser.consume(',') {
			return errors.New("worker JSON object separator is invalid")
		}
		parser.skipSpace()
	}
}

func (parser *workerJSONPreflightV2) parseArray(context workerJSONPreflightContextV2) error {
	if err := parser.enterContainer(); err != nil {
		return err
	}
	defer parser.leaveContainer()
	parser.offset++
	parser.skipSpace()
	if parser.consume(']') {
		return nil
	}
	for {
		if err := parser.parseValue(context); err != nil {
			return err
		}
		parser.skipSpace()
		if parser.consume(']') {
			return nil
		}
		if !parser.consume(',') {
			return errors.New("worker JSON array separator is invalid")
		}
		parser.skipSpace()
	}
}

func (parser *workerJSONPreflightV2) enterContainer() error {
	if parser.depth >= workerJSONPreflightMaxDepthV2 {
		return errors.New("worker JSON nesting exceeds limit")
	}
	parser.depth++
	return nil
}

func (parser *workerJSONPreflightV2) leaveContainer() {
	parser.depth--
}

func workerJSONPreflightChildContextV2(context workerJSONPreflightContextV2, key string) workerJSONPreflightContextV2 {
	switch {
	case context == workerJSONPreflightRootV2 && strings.EqualFold(key, "jobStartV2"):
		return workerJSONPreflightProductionFlagV2
	case context == workerJSONPreflightRootV2 && strings.EqualFold(key, "jobV2"):
		return workerJSONPreflightJobV2
	case context == workerJSONPreflightJobV2 && strings.EqualFold(key, "credentialIntent"):
		return workerJSONPreflightProductionFlagV2
	case workerJSONPreflightTypedContextV2(context) && (strings.EqualFold(key, "env") || strings.EqualFold(key, "labels")):
		return workerJSONPreflightStringMapV2
	case workerJSONPreflightTypedContextV2(context):
		return workerJSONPreflightTypedObjectV2
	default:
		return workerJSONPreflightGenericV2
	}
}

func workerJSONPreflightTypedContextV2(context workerJSONPreflightContextV2) bool {
	switch context {
	case workerJSONPreflightTypedObjectV2,
		workerJSONPreflightRootV2,
		workerJSONPreflightJobV2,
		workerJSONPreflightProductionFlagV2:
		return true
	default:
		return false
	}
}

func (parser *workerJSONPreflightV2) validateRootCanonicalKeys(typedDocument, envelope, storedState bool, jobV2Key, jobV2Token string) error {
	if parser.noncanonicalTypedKey {
		return errors.New("worker JSON typed object key is noncanonical")
	}
	if !typedDocument {
		if jobV2Key != "" {
			return errors.New("worker JSON root schema is ambiguous")
		}
		return nil
	}
	if envelope && storedState {
		return errors.New("worker JSON root schema is ambiguous")
	}
	expectedJobV2Key := "jobV2"
	if storedState {
		expectedJobV2Key = "JobV2"
	}
	if jobV2Key != "" && (jobV2Key != expectedJobV2Key || jobV2Token != `"`+expectedJobV2Key+`"`) {
		return errors.New("worker JSON typed object key is noncanonical")
	}
	return nil
}

func workerJSONPreflightFoldKeyV2(value string) string {
	var folded strings.Builder
	for _, current := range value {
		representative := current
		for candidate := unicode.SimpleFold(current); candidate != current; candidate = unicode.SimpleFold(candidate) {
			if candidate < representative {
				representative = candidate
			}
		}
		folded.WriteRune(unicode.ToLower(representative))
	}
	return folded.String()
}

func (parser *workerJSONPreflightV2) parseString() (string, error) {
	parser.skipSpace()
	if !parser.consume('"') {
		return "", errors.New("worker JSON object key is invalid")
	}
	start := parser.offset - 1
	escaped := false
	for parser.offset < len(parser.raw) {
		current := parser.raw[parser.offset]
		parser.offset++
		if current < 0x20 {
			return "", errors.New("worker JSON string is invalid")
		}
		if escaped {
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
			continue
		}
		if current == '"' {
			quoted := strings.ReplaceAll(parser.raw[start:parser.offset], `\/`, `/`)
			value, err := strconv.Unquote(quoted)
			if err != nil {
				return "", errors.New("worker JSON string is invalid")
			}
			return value, nil
		}
	}
	return "", errors.New("worker JSON string is incomplete")
}

func (parser *workerJSONPreflightV2) parseLiteral(literal string) error {
	if !strings.HasPrefix(parser.raw[parser.offset:], literal) {
		return errors.New("worker JSON literal is invalid")
	}
	parser.offset += len(literal)
	return nil
}

func (parser *workerJSONPreflightV2) parseNumber() error {
	start := parser.offset
	if parser.consume('-') && parser.offset >= len(parser.raw) {
		return errors.New("worker JSON number is invalid")
	}
	if parser.consume('0') {
		if parser.offset < len(parser.raw) && parser.raw[parser.offset] >= '0' && parser.raw[parser.offset] <= '9' {
			return errors.New("worker JSON number is noncanonical")
		}
	} else {
		if parser.offset >= len(parser.raw) || parser.raw[parser.offset] < '1' || parser.raw[parser.offset] > '9' {
			return errors.New("worker JSON number is invalid")
		}
		for parser.offset < len(parser.raw) && parser.raw[parser.offset] >= '0' && parser.raw[parser.offset] <= '9' {
			parser.offset++
		}
	}
	if parser.offset < len(parser.raw) && (parser.raw[parser.offset] == '.' || parser.raw[parser.offset] == 'e' || parser.raw[parser.offset] == 'E') {
		return errors.New("worker JSON number is noncanonical")
	}
	if parser.raw[start:parser.offset] == "-0" {
		return errors.New("worker JSON number is noncanonical")
	}
	return nil
}

func (parser *workerJSONPreflightV2) skipSpace() {
	for parser.offset < len(parser.raw) {
		switch parser.raw[parser.offset] {
		case ' ', '\t', '\r', '\n':
			parser.offset++
		default:
			return
		}
	}
}

func (parser *workerJSONPreflightV2) consume(value byte) bool {
	if parser.offset >= len(parser.raw) || parser.raw[parser.offset] != value {
		return false
	}
	parser.offset++
	return true
}
