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

func readWorkerJSONBounded(reader io.Reader, maxBytes int64) ([]byte, error) {
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
	raw, err := readWorkerJSONBounded(reader, maxBytes)
	if err != nil {
		return err
	}
	if err := validateWorkerJSONPreflight(string(raw)); err != nil {
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
	raw, err := readWorkerJSONBounded(reader, maxBytes)
	if err != nil {
		return err
	}
	if err := validateWorkerJSONPreflight(string(raw)); err != nil {
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

func encodeWorkerResponse(writer io.Writer, response Response) error {
	encoder := json.NewEncoder(writer)
	return encoder.Encode(response)
}

func validateWorkerJSONPreflight(raw string) error {
	if !utf8.ValidString(raw) {
		return errors.New("worker JSON text is invalid")
	}
	parser := workerJSONPreflight{raw: raw}
	if err := parser.parseValue(workerJSONPreflightTypedObject); err != nil {
		return err
	}
	parser.skipSpace()
	if parser.offset != len(parser.raw) {
		return errors.New("worker JSON has trailing data")
	}
	if parser.noncanonicalTypedKey {
		return errors.New("worker JSON typed object key is noncanonical")
	}
	return nil
}

const workerJSONPreflightMaxDepth = 10_000

type workerJSONPreflightContext uint8

const (
	workerJSONPreflightGeneric workerJSONPreflightContext = iota
	workerJSONPreflightTypedObject
	workerJSONPreflightStringMap
)

// workerJSONPreflightCanonicalTags is the union of JSON tags reachable from
// worker requests and responses.
var workerJSONPreflightCanonicalTags = map[string]string{
	"action":                       "action",
	"activationgeneration":         "activationGeneration",
	"activationid":                 "activationId",
	"activemodes":                  "activeModes",
	"activeproofs":                 "activeProofs",
	"activesandboxes":              "activeSandboxes",
	"adapterid":                    "adapterId",
	"algorithm":                    "algorithm",
	"apipath":                      "apiPath",
	"args":                         "args",
	"argv":                         "argv",
	"assetrole":                    "assetRole",
	"assets":                       "assets",
	"backend":                      "backend",
	"bindingid":                    "bindingId",
	"bindingids":                   "bindingIds",
	"cancelrequested":              "cancelRequested",
	"capabilities":                 "capabilities",
	"capability":                   "capability",
	"capabilitylabels":             "capabilityLabels",
	"capacity":                     "capacity",
	"code":                         "code",
	"contractversion":              "contractVersion",
	"controllerkeygeneration":      "controllerKeyGeneration",
	"copyin":                       "copyIn",
	"copyout":                      "copyOut",
	"create":                       "create",
	"credentialdelivery":           "credentialDelivery",
	"credentialgeneration":         "credentialGeneration",
	"credentialmodes":              "credentialModes",
	"credentialproxymode":          "credentialProxyMode",
	"cursor":                       "cursor",
	"data":                         "data",
	"decision":                     "decision",
	"defaultposture":               "defaultPosture",
	"deliverymode":                 "deliveryMode",
	"deliverymodes":                "deliveryModes",
	"destination":                  "destination",
	"digest":                       "digest",
	"digestalgorithm":              "digestAlgorithm",
	"digestvalue":                  "digestValue",
	"displaypath":                  "displayPath",
	"document":                     "document",
	"driver":                       "driver",
	"driverid":                     "driverId",
	"encoding":                     "encoding",
	"enforced":                     "enforced",
	"enforcementmode":              "enforcementMode",
	"env":                          "env",
	"environment":                  "environment",
	"error":                        "error",
	"errorcodes":                   "errorCodes",
	"errorcount":                   "errorCount",
	"exec":                         "exec",
	"executionid":                  "executionId",
	"executablerole":               "executableRole",
	"exitcode":                     "exitCode",
	"failurecode":                  "failureCode",
	"finishedat":                   "finishedAt",
	"firecrackerprocessgeneration": "firecrackerProcessGeneration",
	"guestbootgeneration":          "guestBootGeneration",
	"guesthelpergeneration":        "guestHelperGeneration",
	"guestimagedigest":             "guestImageDigest",
	"guestimagegeneration":         "guestImageGeneration",
	"guestsessiongeneration":       "guestSessionGeneration",
	"guestreadiness":               "guestReadiness",
	"health":                       "health",
	"heartbeatat":                  "heartbeatAt",
	"hostid":                       "hostId",
	"hostkind":                     "hostKind",
	"id":                           "id",
	"image":                        "image",
	"identity":                     "identity",
	"issuedat":                     "issuedAt",
	"inspect":                      "inspect",
	"isolationlevel":               "isolationLevel",
	"job":                          "job",
	"jobcancel":                    "jobCancel",
	"jobid":                        "jobId",
	"joblogs":                      "jobLogs",
	"jobresolve":                   "jobResolve",
	"jobstart":                     "jobStart",
	"jobstatus":                    "jobStatus",
	"labels":                       "labels",
	"lifecycle":                    "lifecycle",
	"limitbytes":                   "limitBytes",
	"limitexceeded":                "limitExceeded",
	"lockstatus":                   "lockStatus",
	"lockedat":                     "lockedAt",
	"logcursor":                    "logCursor",
	"logtruncated":                 "logTruncated",
	"maxconcurrentsandboxes":       "maxConcurrentSandboxes",
	"maxpayloadbytes":              "maxPayloadBytes",
	"mechanisms":                   "mechanisms",
	"message":                      "message",
	"metadata":                     "metadata",
	"mode":                         "mode",
	"modes":                        "modes",
	"name":                         "name",
	"networkenforcement":           "networkEnforcement",
	"networkenforcementcapability": "networkEnforcementCapability",
	"networkpolicy":                "networkPolicy",
	"networkplanid":                "networkPlanId",
	"nextcursor":                   "nextCursor",
	"ok":                           "ok",
	"oldestcursor":                 "oldestCursor",
	"operation":                    "operation",
	"operationid":                  "operationId",
	"operationplan":                "operationPlan",
	"operations":                   "operations",
	"orchestration":                "orchestration",
	"outcome":                      "outcome",
	"pathrole":                     "pathRole",
	"pathroles":                    "pathRoles",
	"payload":                      "payload",
	"payloads":                     "payloads",
	"plan":                         "plan",
	"planid":                       "planId",
	"policypreset":                 "policyPreset",
	"policysnapshotid":             "policySnapshotId",
	"processdescriptor":            "processDescriptor",
	"processid":                    "processId",
	"processidsource":              "processIdSource",
	"processlaunch":                "processLaunch",
	"proofid":                      "proofId",
	"protocolversion":              "protocolVersion",
	"provenancelabels":             "provenanceLabels",
	"proxy":                        "proxy",
	"proxygenerationid":            "proxyGenerationId",
	"proxysessionid":               "proxySessionId",
	"reasoncode":                   "reasonCode",
	"reasoncodes":                  "reasonCodes",
	"records":                      "records",
	"referencekind":                "referenceKind",
	"remotedestinationpath":        "remoteDestinationPath",
	"remotesourcepath":             "remoteSourcePath",
	"request":                      "request",
	"requestid":                    "requestId",
	"requestkey":                   "requestKey",
	"requested":                    "requested",
	"requestedmodes":               "requestedModes",
	"result":                       "result",
	"revision":                     "revision",
	"role":                         "role",
	"rulegenerationid":             "ruleGenerationId",
	"rules":                        "rules",
	"runtime":                      "runtime",
	"runtimedriver":                "runtimeDriver",
	"runtimedrivers":               "runtimeDrivers",
	"runtimegeneration":            "runtimeGeneration",
	"runtimeid":                    "runtimeId",
	"runtimeimage":                 "runtimeImage",
	"security":                     "security",
	"seed":                         "seed",
	"serviceid":                    "serviceId",
	"sizebytes":                    "sizeBytes",
	"socketpath":                   "socketPath",
	"source":                       "source",
	"sourceartifact":               "sourceArtifact",
	"sourcekind":                   "sourceKind",
	"sourcereferenceid":            "sourceReferenceId",
	"startedat":                    "startedAt",
	"state":                        "state",
	"status":                       "status",
	"stderr":                       "stderr",
	"stderrlimitbytes":             "stderrLimitBytes",
	"stderrtruncated":              "stderrTruncated",
	"stdin":                        "stdin",
	"stdout":                       "stdout",
	"stdoutlimitbytes":             "stdoutLimitBytes",
	"stdouttruncated":              "stdoutTruncated",
	"stream":                       "stream",
	"submissionid":                 "submissionId",
	"submissionkey":                "submissionKey",
	"submittedat":                  "submittedAt",
	"supported":                    "supported",
	"supportedoperations":          "supportedOperations",
	"supportedruntimedrivers":      "supportedRuntimeDrivers",
	"supportsdefaultdenyposture":   "supportsDefaultDenyPosture",
	"supportsdomainrules":          "supportsDomainRules",
	"supportsendpointrules":        "supportsEnd" + "pointRules",
	"supportslinklocalrules":       "supportsLinkLocalRules",
	"supportsloopbackrules":        "supportsLoopbackRules",
	"supportsmetadataendpoint":     "supportsMetadataEnd" + "point",
	"supportsprivaterangerules":    "supportsPrivateRangeRules",
	"target":                       "target",
	"templatelock":                 "templateLock",
	"templatereference":            "templateReference",
	"templatestatus":               "templateStatus",
	"timestamp":                    "timestamp",
	"topologygenerationid":         "topologyGenerationId",
	"transport":                    "transport",
	"truncated":                    "truncated",
	"trustdecision":                "trustDecision",
	"trustmode":                    "trustMode",
	"trustpolicy":                  "trustPolicy",
	"value":                        "value",
	"vsockgeneration":              "vsockGeneration",
	"warningcodes":                 "warningCodes",
	"warningcount":                 "warningCount",
	"workdir":                      "workDir",
	"workerid":                     "workerId",
	"workerjobid":                  "workerJobId",
}

type workerJSONPreflight struct {
	raw                  string
	offset               int
	depth                int
	noncanonicalTypedKey bool
}

func (parser *workerJSONPreflight) parseValue(context workerJSONPreflightContext) error {
	parser.skipSpace()
	if parser.offset >= len(parser.raw) {
		return errors.New("worker JSON is incomplete")
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

func (parser *workerJSONPreflight) parseObject(context workerJSONPreflightContext) error {
	if err := parser.enterContainer(); err != nil {
		return err
	}
	defer parser.leaveContainer()
	parser.offset++
	parser.skipSpace()
	seen := make(map[string]bool)
	seenFolded := make(map[string]bool)
	if parser.consume('}') {
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
		if context == workerJSONPreflightTypedObject {
			folded := workerJSONPreflightFoldKey(key)
			if seenFolded[folded] {
				return errors.New("worker JSON contains duplicate object key")
			}
			seenFolded[folded] = true
			if canonical, known := workerJSONPreflightCanonicalTags[folded]; known && (key != canonical || keyToken != `"`+canonical+`"`) {
				parser.noncanonicalTypedKey = true
			}
		}
		parser.skipSpace()
		if !parser.consume(':') {
			return errors.New("worker JSON object separator is invalid")
		}
		parser.skipSpace()
		if err := parser.parseValue(workerJSONPreflightChildContext(context, key)); err != nil {
			return err
		}
		parser.skipSpace()
		if parser.consume('}') {
			return nil
		}
		if !parser.consume(',') {
			return errors.New("worker JSON object separator is invalid")
		}
		parser.skipSpace()
	}
}

func (parser *workerJSONPreflight) parseArray(context workerJSONPreflightContext) error {
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

func (parser *workerJSONPreflight) enterContainer() error {
	if parser.depth >= workerJSONPreflightMaxDepth {
		return errors.New("worker JSON nesting exceeds limit")
	}
	parser.depth++
	return nil
}

func (parser *workerJSONPreflight) leaveContainer() {
	parser.depth--
}

func workerJSONPreflightChildContext(context workerJSONPreflightContext, key string) workerJSONPreflightContext {
	switch {
	case context == workerJSONPreflightTypedObject && (strings.EqualFold(key, "env") || strings.EqualFold(key, "labels")):
		return workerJSONPreflightStringMap
	case context == workerJSONPreflightTypedObject:
		return workerJSONPreflightTypedObject
	default:
		return workerJSONPreflightGeneric
	}
}

func workerJSONPreflightFoldKey(value string) string {
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

func (parser *workerJSONPreflight) parseString() (string, error) {
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
			quoted := workerJSONSlashEscapesForUnquote(parser.raw[start:parser.offset])
			value, err := strconv.Unquote(quoted)
			if err != nil {
				return "", errors.New("worker JSON string is invalid")
			}
			return value, nil
		}
	}
	return "", errors.New("worker JSON string is incomplete")
}

// strconv.Unquote accepts Go string syntax, so genuine JSON slash escapes need
// normalization. Skip complete escape pairs: the slash after an escaped
// backslash is literal, and removing that backslash would change its meaning.
func workerJSONSlashEscapesForUnquote(quoted string) string {
	var normalized strings.Builder
	start := 0
	for index := 0; index+1 < len(quoted); index++ {
		if quoted[index] != '\\' {
			continue
		}
		if quoted[index+1] == '/' {
			normalized.WriteString(quoted[start:index])
			start = index + 1
		}
		index++
	}
	if start == 0 {
		return quoted
	}
	normalized.WriteString(quoted[start:])
	return normalized.String()
}

func (parser *workerJSONPreflight) parseLiteral(literal string) error {
	if !strings.HasPrefix(parser.raw[parser.offset:], literal) {
		return errors.New("worker JSON literal is invalid")
	}
	parser.offset += len(literal)
	return nil
}

func (parser *workerJSONPreflight) parseNumber() error {
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

func (parser *workerJSONPreflight) skipSpace() {
	for parser.offset < len(parser.raw) {
		switch parser.raw[parser.offset] {
		case ' ', '\t', '\r', '\n':
			parser.offset++
		default:
			return
		}
	}
}

func (parser *workerJSONPreflight) consume(value byte) bool {
	if parser.offset >= len(parser.raw) || parser.raw[parser.offset] != value {
		return false
	}
	parser.offset++
	return true
}
