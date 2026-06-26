package ci

import (
	"reflect"
	"testing"
)

func TestGitHubPushAuthEnvUsesTokenForGitHubSSHRewrite(t *testing.T) {
	t.Parallel()

	secret := "ghp_ci_push_secret_1234567890"
	got := gitHubPushAuthEnv(func(key string) string {
		if key == githubTokenEnv {
			return secret
		}
		return ""
	})

	want := map[string]string{
		"GIT_CONFIG_COUNT":   "3",
		"GIT_CONFIG_KEY_0":   gitHubExtraHeaderKey,
		"GIT_CONFIG_VALUE_0": gitHubAuthHeader(secret),
		"GIT_CONFIG_KEY_1":   gitHubURLRewriteKey,
		"GIT_CONFIG_VALUE_1": "git@github.com:",
		"GIT_CONFIG_KEY_2":   gitHubURLRewriteKey,
		"GIT_CONFIG_VALUE_2": "ssh://git@github.com/",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gitHubPushAuthEnv() mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestGitHubPushAuthEnvUsesGHTokenAfterExistingGitConfig(t *testing.T) {
	t.Parallel()

	secret := "ghp_ci_push_gh_secret_1234567890"
	got := gitHubPushAuthEnv(func(key string) string {
		switch key {
		case ghTokenEnv:
			return secret
		case "GIT_CONFIG_COUNT":
			return "2"
		default:
			return ""
		}
	})

	want := map[string]string{
		"GIT_CONFIG_COUNT":   "5",
		"GIT_CONFIG_KEY_2":   gitHubExtraHeaderKey,
		"GIT_CONFIG_VALUE_2": gitHubAuthHeader(secret),
		"GIT_CONFIG_KEY_3":   gitHubURLRewriteKey,
		"GIT_CONFIG_VALUE_3": "git@github.com:",
		"GIT_CONFIG_KEY_4":   gitHubURLRewriteKey,
		"GIT_CONFIG_VALUE_4": "ssh://git@github.com/",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gitHubPushAuthEnv() mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestGitHubPushAuthEnvSkipsWhenTokenMissing(t *testing.T) {
	t.Parallel()

	got := gitHubPushAuthEnv(func(string) string { return "" })
	if got != nil {
		t.Fatalf("gitHubPushAuthEnv() = %#v, want nil", got)
	}
}
