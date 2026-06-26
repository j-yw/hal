package ci

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	gitHubExtraHeaderKey = "http.https://github.com/.extraheader"
	gitHubURLRewriteKey  = "url.https://github.com/.insteadOf"
)

type gitConfigEntry struct {
	key   string
	value string
}

func gitHubPushAuthEnv(getenv func(string) string) map[string]string {
	if getenv == nil {
		getenv = os.Getenv
	}

	token, ok := envToken(getenv)
	if !ok {
		return nil
	}

	header := gitHubAuthHeader(token)
	if header == "" {
		return nil
	}

	configs := []gitConfigEntry{
		{key: gitHubExtraHeaderKey, value: header},
		{key: gitHubURLRewriteKey, value: "git@github.com:"},
		{key: gitHubURLRewriteKey, value: "ssh://git@github.com/"},
	}

	index := gitConfigIndex(getenv)
	env := map[string]string{
		"GIT_CONFIG_COUNT": strconv.Itoa(index + len(configs)),
	}
	for offset, config := range configs {
		configIndex := index + offset
		env[fmt.Sprintf("GIT_CONFIG_KEY_%d", configIndex)] = config.key
		env[fmt.Sprintf("GIT_CONFIG_VALUE_%d", configIndex)] = config.value
	}
	return env
}

func gitConfigIndex(getenv func(string) string) int {
	if getenv == nil {
		getenv = os.Getenv
	}
	count, err := strconv.Atoi(strings.TrimSpace(getenv("GIT_CONFIG_COUNT")))
	if err != nil || count < 0 {
		return 0
	}
	return count
}

func gitHubAuthHeader(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	credential := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	return "AUTHORIZATION: basic " + credential
}
