package registry_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/registry"
)

func TestL9StrictReferenceParsingRejectsAmbiguousOrUnsafeInput(t *testing.T) {
	tests := []string{
		"",
		"registry.example",
		"registry.example/repo",
		"registry.example//repo:tag",
		"registry.example/./repo:tag",
		"registry.example/a/../repo:tag",
		"registry.example/%2e/repo:tag",
		"registry.example/repo%2ftemplate:tag",
		"registry.example/repo\\template:tag",
		"registry.example/repo:tag?token=secret",
		"registry.example/repo:tag#fragment",
		"user:password@registry.example/repo:tag",
		"https://registry.example/repo:tag",
		"http://registry.example/repo:tag",
		"registry.example/repo:",
		"registry.example/UPPER/repo:tag",
		"registry.example/repo:tag@sha256:" + strings.Repeat("a", 64),
		"registry.example/repo:\nlatest",
		"127.0.0.1/repo:tag",
		"[::1]/repo:tag",
		"169.254.169.254/latest/meta-data:tag",
	}
	for _, ref := range tests {
		t.Run(strings.ReplaceAll(ref, "/", "_"), func(t *testing.T) {
			called := false
			resolver, err := registry.NewResolver(registry.Options{
				Client: fakeHTTPDoer(func(*http.Request) (*http.Response, error) {
					called = true
					return nil, errors.New("must not be called")
				}),
				AllowedRegistryOrigins: []string{registryOrigin},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, resolveErr := resolver.ResolveOCIArtifact(context.Background(), acquisition.OCIArtifactResolveRequest{
				Reference: sandboxtemplate.ImmutableRef{
					Kind: sandboxtemplate.ReferenceKindOCIArtifact,
					Ref:  ref,
				},
			})
			requireRegistryErrorCode(t, resolveErr, registry.ErrorCodeInvalidReference)
			if called {
				t.Fatal("invalid reference reached HTTP dependency")
			}
		})
	}
}

func TestL9StaticReferenceValidationUsesStrictParserWithoutDependencies(t *testing.T) {
	validated, err := registry.ValidateReference(sandboxtemplate.ImmutableRef{
		Kind: sandboxtemplate.ReferenceKindOCIArtifact,
		Ref:  "registry.example/hal/template:latest",
	})
	if err != nil {
		t.Fatalf("ValidateReference() error = %v", err)
	}
	if validated.Authority != "registry.example" {
		t.Fatalf("ValidateReference() authority = %q", validated.Authority)
	}
	for _, ref := range []string{
		" https://registry.example/hal/template:latest ",
		"registry.example/hal/../template:latest",
		"registry.example/hal/template",
		"registry.example/hal/template:bad tag",
		"REGISTRY.example/hal/template:latest",
		"registry.example:99999/hal/template:latest",
	} {
		_, validateErr := registry.ValidateReference(sandboxtemplate.ImmutableRef{
			Kind: sandboxtemplate.ReferenceKindOCIArtifact,
			Ref:  ref,
		})
		requireRegistryErrorCode(t, validateErr, registry.ErrorCodeInvalidReference)
		if strings.Contains(validateErr.Error(), ref) {
			t.Fatalf("validation error leaked caller reference %q", ref)
		}
	}
}

func TestL9StaticReferenceValidationNormalizesStandardDigestPinnedReference(t *testing.T) {
	const digestValue = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	validated, err := registry.ValidateReference(sandboxtemplate.ImmutableRef{
		Kind: sandboxtemplate.ReferenceKindOCIArtifact,
		Ref:  "registry.example/hal/template@sha256:" + digestValue,
	})
	if err != nil {
		t.Fatalf("ValidateReference() error = %v", err)
	}
	if validated.Authority != "registry.example" ||
		validated.Reference.Ref != "registry.example/hal/template" ||
		validated.Reference.Digest == nil ||
		validated.Reference.Digest.Algorithm != sandboxtemplate.DigestAlgorithmSHA256 ||
		validated.Reference.Digest.Value != digestValue {
		t.Fatalf("validated digest reference = %#v", validated)
	}
}

func TestL9StaticReferenceValidationRejectsAmbiguousOrMalformedInlineDigest(t *testing.T) {
	for _, ref := range []string{
		"registry.example/hal/template:latest@sha256:" + strings.Repeat("a", 64),
		"registry.example/hal/template@SHA256:" + strings.Repeat("a", 64),
		"registry.example/hal/template@sha512:" + strings.Repeat("a", 64),
		"registry.example/hal/template@sha256:" + strings.Repeat("A", 64),
		"registry.example/hal/template@sha256:short",
		"registry.example/hal/template@sha256:" + strings.Repeat("a", 64) + "@sha256:" + strings.Repeat("b", 64),
		"user@registry.example/hal/template:latest",
		"registry.example/hal/template@sha256:" + strings.Repeat("a", 64) + "?token=secret",
		"registry.example/hal/template@sha256:" + strings.Repeat("a", 64) + "#fragment",
	} {
		_, err := registry.ValidateReference(sandboxtemplate.ImmutableRef{
			Kind: sandboxtemplate.ReferenceKindOCIArtifact,
			Ref:  ref,
		})
		requireRegistryErrorCode(t, err, registry.ErrorCodeInvalidReference)
		if strings.Contains(err.Error(), ref) {
			t.Fatalf("validation error leaked reference %q", ref)
		}
	}
	_, err := registry.ValidateReference(sandboxtemplate.ImmutableRef{
		Kind: sandboxtemplate.ReferenceKindOCIArtifact,
		Ref:  "registry.example/hal/template@sha256:" + strings.Repeat("a", 64),
		Digest: &sandboxtemplate.DigestMetadata{
			Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
			Value:     strings.Repeat("b", 64),
		},
	})
	requireRegistryErrorCode(t, err, registry.ErrorCodeInvalidReference)
}

func TestL9RegistryOriginMustBeExactAllowlistedOrigin(t *testing.T) {
	for _, ref := range []string{
		"evil.example/hal/template:latest",
		"registry.example.evil/hal/template:latest",
		"REGISTRY.example/hal/template:latest",
		"registry.example:444/hal/template:latest",
	} {
		t.Run(ref, func(t *testing.T) {
			called := false
			resolver := mustRegistryResolver(t, fakeHTTPDoer(func(*http.Request) (*http.Response, error) {
				called = true
				return nil, nil
			}), nil)
			_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest(ref))
			requireRegistryErrorCode(t, err, registry.ErrorCodeInvalidReference)
			if called {
				t.Fatal("non-allowlisted origin reached transport")
			}
		})
	}
}

func TestL9RegistryOriginRejectsConflictingSchemesForOneAuthority(t *testing.T) {
	_, err := registry.NewResolver(registry.Options{
		Client:                 fakeHTTPDoer(func(*http.Request) (*http.Response, error) { return nil, nil }),
		AllowedRegistryOrigins: []string{"https://registry.example", "http://registry.example"},
		PlainHTTPOrigins:       []string{"http://registry.example"},
	})
	if err == nil {
		t.Fatal("NewResolver() accepted HTTPS and plain HTTP for the same authority")
	}
}

func TestL9DialPolicyRejectsNonPublicDestinationsAndDNSRebinding(t *testing.T) {
	public := netip.MustParseAddr("8.8.8.8")
	private := netip.MustParseAddr("127.0.0.1")
	lookupCalls := 0
	dialCalls := 0
	policy, err := registry.NewDialPolicy(registry.DialPolicyOptions{
		LookupNetIP: func(context.Context, string) ([]netip.Addr, error) {
			lookupCalls++
			if lookupCalls == 1 {
				return []netip.Addr{public}, nil
			}
			return []netip.Addr{private}, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialCalls++
			return nil, errors.New("fixture dial")
		},
	})
	if err != nil {
		t.Fatalf("NewDialPolicy() error = %v", err)
	}
	_, _ = policy.DialContext(context.Background(), "tcp", "registry.example:443")
	_, secondErr := policy.DialContext(context.Background(), "tcp", "registry.example:443")
	if secondErr == nil || !strings.Contains(secondErr.Error(), string(registry.ErrorCodeAddressRejected)) {
		t.Fatalf("second dial error = %v, want address_rejected", secondErr)
	}
	if dialCalls != 1 {
		t.Fatalf("underlying dial calls = %d, want private rebound rejected before second dial", dialCalls)
	}
}

func TestL9DialPolicyRejectsEveryForbiddenAddressClass(t *testing.T) {
	for _, raw := range []string{
		"0.0.0.0",
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.1",
		"169.254.169.254",
		"224.0.0.1",
		"::",
		"::1",
		"fe80::1",
		"fc00::1",
		"ff02::1",
		"240.0.0.1",
		"255.255.255.255",
	} {
		t.Run(raw, func(t *testing.T) {
			if err := registry.ValidateDialAddress(netip.MustParseAddr(raw), false); err == nil {
				t.Fatalf("ValidateDialAddress(%s) = nil", raw)
			}
		})
	}
}

func TestL9DialPolicyRejectsMalformedNonPublicOriginExceptions(t *testing.T) {
	address := netip.MustParseAddr("127.0.0.1")
	for _, origin := range []string{
		"",
		"http://registry.internal.example",
		"https://user:pass@registry.internal.example",
		"https://registry.internal.example/path",
		"https://registry.internal.example?query=1",
		"https://registry.internal.example#fragment",
	} {
		t.Run(origin, func(t *testing.T) {
			_, err := registry.NewDialPolicy(registry.DialPolicyOptions{
				NonPublicOriginExceptions: []registry.NonPublicOriginException{{
					Origin:  origin,
					Address: address,
				}},
			})
			if err == nil {
				t.Fatalf("NewDialPolicy() accepted malformed exception origin %q", origin)
			}
		})
	}
	if _, err := registry.NewDialPolicy(registry.DialPolicyOptions{
		NonPublicOriginExceptions: []registry.NonPublicOriginException{{
			Origin: "https://registry.internal.example",
		}},
	}); err == nil {
		t.Fatal("NewDialPolicy() accepted invalid exception address")
	}
}

func TestL9TrustedInternalOriginExceptionIsExact(t *testing.T) {
	private := netip.MustParseAddr("10.20.30.40")
	if err := registry.ValidateOriginAddress("https://registry.internal.example", private, []registry.NonPublicOriginException{{
		Origin:  "https://registry.internal.example",
		Address: private,
	}}); err != nil {
		t.Fatalf("exact trusted internal exception error = %v", err)
	}
	for _, origin := range []string{
		"https://registry.internal.example.evil",
		"http://registry.internal.example",
		"https://registry.internal.example:444",
	} {
		if err := registry.ValidateOriginAddress(origin, private, []registry.NonPublicOriginException{{
			Origin:  "https://registry.internal.example",
			Address: private,
		}}); err == nil {
			t.Fatalf("non-exact origin %q accepted private address", origin)
		}
	}
}

func TestL9ProductionTransportDisablesAmbientProxyAndLocksTLSMinimum(t *testing.T) {
	transport, err := registry.NewProductionTransport(registry.ProductionTransportOptions{})
	if err != nil {
		t.Fatalf("NewProductionTransport() error = %v", err)
	}
	if transport.Proxy != nil {
		t.Fatal("production transport inherited ambient proxy behavior")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("TLS minimum = %#v, want TLS 1.2+", transport.TLSClientConfig)
	}
	if transport.MaxResponseHeaderBytes != registry.DefaultMaxResponseHeaderBytes {
		t.Fatalf("MaxResponseHeaderBytes = %d, want %d", transport.MaxResponseHeaderBytes, registry.DefaultMaxResponseHeaderBytes)
	}
	client, err := registry.NewProductionClient(registry.ProductionClientOptions{})
	if err != nil {
		t.Fatalf("NewProductionClient() error = %v", err)
	}
	redirectRequest, _ := http.NewRequest(http.MethodGet, "https://redirect.example", nil)
	if err := client.CheckRedirect(redirectRequest, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect() error = %v, want ErrUseLastResponse", err)
	}
}

func TestL9DefaultRegistryTestsContainNoLiveListener(t *testing.T) {
	// This source guard makes the fake-only default boundary auditable. The
	// build-tagged integration file is intentionally outside this scan.
	for _, source := range []string{
		"resolver_red_test.go",
		"auth_redirect_red_test.go",
		"reference_origin_red_test.go",
		"cache_red_test.go",
	} {
		content, err := osReadFile(source)
		if err != nil {
			t.Fatalf("read %s: %v", source, err)
		}
		for _, forbidden := range []string{"httptest." + "NewServer", "net." + "Listen(", "ListenAnd" + "Serve"} {
			if strings.Contains(string(content), forbidden) {
				t.Fatalf("%s contains live-listener marker %q", source, forbidden)
			}
		}
	}
}

var osReadFile = func(path string) ([]byte, error) {
	return os.ReadFile(path)
}
