package authmw

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testSecret = "test-secret-key-for-hmac-sha256"

// buildJWT creates a signed HS256 JWT for testing.
func buildJWT(t *testing.T, secret string, header map[string]string, claims map[string]interface{}) string {
	t.Helper()

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64
}

// validJWT creates a valid JWT with standard claims for testing.
func validJWT(t *testing.T) string {
	t.Helper()
	return buildJWT(t, testSecret,
		map[string]string{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{
			"sub": "operator-1",
			"iss": "hal-cloud",
			"aud": "hal-control-plane",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		},
	)
}

// okHandler is a simple handler that returns 200 OK for authenticated requests.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
}

func TestMiddleware_MissingAuthorizationHeader(t *testing.T) {
	mw := Middleware(Config{
		JWTSecret:   testSecret,
		JWTIssuer:   "hal-cloud",
		JWTAudience: "hal-control-plane",
	})

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	assertUnauthorizedJSON(t, rec)
}

func TestMiddleware_EmptyBearerToken(t *testing.T) {
	mw := Middleware(Config{
		JWTSecret:   testSecret,
		JWTIssuer:   "hal-cloud",
		JWTAudience: "hal-control-plane",
	})

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	assertUnauthorizedJSON(t, rec)
}

func TestMiddleware_NonBearerScheme(t *testing.T) {
	mw := Middleware(Config{
		JWTSecret:   testSecret,
		JWTIssuer:   "hal-cloud",
		JWTAudience: "hal-control-plane",
	})

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	assertUnauthorizedJSON(t, rec)
}

func TestMiddleware_ValidJWT(t *testing.T) {
	mw := Middleware(Config{
		JWTSecret:   testSecret,
		JWTIssuer:   "hal-cloud",
		JWTAudience: "hal-control-plane",
	})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil {
			t.Error("expected claims in context")
			return
		}
		if claims.Subject != "operator-1" {
			t.Errorf("expected subject operator-1, got %s", claims.Subject)
		}
		identity := IdentityFromContext(r.Context())
		if identity != "operator-1" {
			t.Errorf("expected identity operator-1, got %s", identity)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+validJWT(t))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestMiddleware_ExpiredJWT(t *testing.T) {
	expired := buildJWT(t, testSecret,
		map[string]string{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{
			"sub": "operator-1",
			"iss": "hal-cloud",
			"aud": "hal-control-plane",
			"exp": time.Now().Add(-time.Hour).Unix(),
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
		},
	)

	mw := Middleware(Config{
		JWTSecret:   testSecret,
		JWTIssuer:   "hal-cloud",
		JWTAudience: "hal-control-plane",
	})

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+expired)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	assertUnauthorizedJSON(t, rec)
}

func TestMiddleware_WrongJWTIssuer(t *testing.T) {
	wrongIssuer := buildJWT(t, testSecret,
		map[string]string{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{
			"sub": "operator-1",
			"iss": "wrong-issuer",
			"aud": "hal-control-plane",
			"exp": time.Now().Add(time.Hour).Unix(),
		},
	)

	mw := Middleware(Config{
		JWTSecret:   testSecret,
		JWTIssuer:   "hal-cloud",
		JWTAudience: "hal-control-plane",
	})

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+wrongIssuer)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	assertUnauthorizedJSON(t, rec)
}

func TestMiddleware_WrongJWTAudience(t *testing.T) {
	wrongAudience := buildJWT(t, testSecret,
		map[string]string{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{
			"sub": "operator-1",
			"iss": "hal-cloud",
			"aud": "wrong-audience",
			"exp": time.Now().Add(time.Hour).Unix(),
		},
	)

	mw := Middleware(Config{
		JWTSecret:   testSecret,
		JWTIssuer:   "hal-cloud",
		JWTAudience: "hal-control-plane",
	})

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+wrongAudience)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	assertUnauthorizedJSON(t, rec)
}

func TestMiddleware_WrongJWTSecret(t *testing.T) {
	wrongSecret := buildJWT(t, "wrong-secret",
		map[string]string{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{
			"sub": "operator-1",
			"iss": "hal-cloud",
			"aud": "hal-control-plane",
			"exp": time.Now().Add(time.Hour).Unix(),
		},
	)

	mw := Middleware(Config{
		JWTSecret:   testSecret,
		JWTIssuer:   "hal-cloud",
		JWTAudience: "hal-control-plane",
	})

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+wrongSecret)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	assertUnauthorizedJSON(t, rec)
}

func TestMiddleware_UnsupportedJWTAlgorithm(t *testing.T) {
	// Create a token with RS256 header but signed with HMAC (should be rejected).
	badAlg := buildJWT(t, testSecret,
		map[string]string{"alg": "RS256", "typ": "JWT"},
		map[string]interface{}{
			"sub": "operator-1",
			"iss": "hal-cloud",
			"aud": "hal-control-plane",
			"exp": time.Now().Add(time.Hour).Unix(),
		},
	)

	mw := Middleware(Config{
		JWTSecret:   testSecret,
		JWTIssuer:   "hal-cloud",
		JWTAudience: "hal-control-plane",
	})

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+badAlg)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	assertUnauthorizedJSON(t, rec)
}

func TestMiddleware_ValidPAT(t *testing.T) {
	pat := "halp_1234567890abcdef"

	mw := Middleware(Config{
		PATAllowlist: []string{pat},
	})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := IdentityFromContext(r.Context())
		if !strings.HasPrefix(identity, "pat:") {
			t.Errorf("expected pat: prefix, got %s", identity)
		}
		if identity != "pat:halp_123" {
			t.Errorf("expected pat:halp_123, got %s", identity)
		}
		// PAT-authenticated requests should not have JWT claims.
		if claims := ClaimsFromContext(r.Context()); claims != nil {
			t.Error("expected nil claims for PAT auth")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+pat)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestMiddleware_InvalidPAT(t *testing.T) {
	mw := Middleware(Config{
		PATAllowlist: []string{"halp_valid_token"},
	})

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer halp_invalid_token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	assertUnauthorizedJSON(t, rec)
}

func TestMiddleware_JWTPreferredOverPAT(t *testing.T) {
	// When both JWT and PAT are configured, a valid JWT should use JWT auth.
	jwt := validJWT(t)

	mw := Middleware(Config{
		JWTSecret:    testSecret,
		JWTIssuer:    "hal-cloud",
		JWTAudience:  "hal-control-plane",
		PATAllowlist: []string{jwt}, // Token also in PAT list (unlikely but tests precedence)
	})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil {
			t.Error("expected JWT claims (JWT should take precedence)")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestMiddleware_PATFallbackWhenJWTFails(t *testing.T) {
	pat := "not-a-jwt-token"

	mw := Middleware(Config{
		JWTSecret:    testSecret,
		JWTIssuer:    "hal-cloud",
		JWTAudience:  "hal-control-plane",
		PATAllowlist: []string{pat},
	})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should fall through to PAT since token isn't a valid JWT.
		identity := IdentityFromContext(r.Context())
		if !strings.HasPrefix(identity, "pat:") {
			t.Errorf("expected pat: prefix, got %s", identity)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+pat)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestMiddleware_BearerCaseInsensitive(t *testing.T) {
	mw := Middleware(Config{
		JWTSecret:   testSecret,
		JWTIssuer:   "hal-cloud",
		JWTAudience: "hal-control-plane",
	})

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "BEARER "+validJWT(t))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (Bearer should be case-insensitive)", rec.Code)
	}
}

func TestMiddleware_NeitherJWTNorPATConfigured(t *testing.T) {
	mw := Middleware(Config{})

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no auth is configured, got %d", rec.Code)
	}
	assertUnauthorizedJSON(t, rec)
}

func TestMiddleware_EmptyPATInAllowlistIgnored(t *testing.T) {
	mw := Middleware(Config{
		PATAllowlist: []string{"", "valid-pat"},
	})

	handler := mw(okHandler())

	// Empty bearer token should not match the empty string in allowlist.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for empty bearer, got %d", rec.Code)
	}
}

func TestMiddleware_MalformedJWT(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"single_segment", "abc"},
		{"two_segments", "abc.def"},
		{"four_segments", "abc.def.ghi.jkl"},
		{"empty_segments", ".."},
		{"invalid_base64_header", "!!!.def.ghi"},
	}

	mw := Middleware(Config{
		JWTSecret: testSecret,
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := mw(okHandler())
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401 for malformed JWT %q, got %d", tt.token, rec.Code)
			}
			assertUnauthorizedJSON(t, rec)
		})
	}
}

func TestMiddleware_JWTWithoutExpClaim(t *testing.T) {
	// JWT without exp claim should be accepted (exp=0 is treated as no expiry).
	noExp := buildJWT(t, testSecret,
		map[string]string{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{
			"sub": "operator-1",
			"iss": "hal-cloud",
			"aud": "hal-control-plane",
		},
	)

	mw := Middleware(Config{
		JWTSecret:   testSecret,
		JWTIssuer:   "hal-cloud",
		JWTAudience: "hal-control-plane",
	})

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+noExp)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for JWT without exp, got %d", rec.Code)
	}
}

func TestMiddleware_ResponseContentType(t *testing.T) {
	mw := Middleware(Config{JWTSecret: testSecret})

	handler := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("expected application/json content type, got %s", ct)
	}
}

func TestClaimsFromContext_NoClaims(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if claims := ClaimsFromContext(req.Context()); claims != nil {
		t.Error("expected nil claims from empty context")
	}
}

func TestIdentityFromContext_NoIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if identity := IdentityFromContext(req.Context()); identity != "" {
		t.Errorf("expected empty identity from empty context, got %s", identity)
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantToken string
		wantOK    bool
	}{
		{"empty", "", "", false},
		{"basic_auth", "Basic dXNlcjpwYXNz", "", false},
		{"bearer_lowercase", "bearer mytoken", "mytoken", true},
		{"bearer_mixed_case", "Bearer MyToken", "MyToken", true},
		{"bearer_uppercase", "BEARER mytoken", "mytoken", true},
		{"bearer_with_spaces", "Bearer   spaced-token  ", "spaced-token", true},
		{"bearer_empty_token", "Bearer ", "", false},
		{"bearer_only", "Bearer", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			token, ok := extractBearerToken(req)
			if ok != tt.wantOK {
				t.Errorf("ok=%v, want %v", ok, tt.wantOK)
			}
			if token != tt.wantToken {
				t.Errorf("token=%q, want %q", token, tt.wantToken)
			}
		})
	}
}

func TestTruncateToken(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"short", "short"},
		{"12345678", "12345678"},
		{"123456789", "12345678"},
		{"halp_1234567890abcdef", "halp_123"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := truncateToken(tt.input)
			if got != tt.want {
				t.Errorf("truncateToken(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// assertUnauthorizedJSON checks that the response body contains the expected error JSON.
func assertUnauthorizedJSON(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	var resp errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.ErrorCode != "unauthorized" {
		t.Errorf("expected error_code unauthorized, got %q", resp.ErrorCode)
	}
	if resp.Error == "" {
		t.Error("expected non-empty error message")
	}
}
