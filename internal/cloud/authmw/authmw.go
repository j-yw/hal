package authmw

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Config holds the configuration for the auth middleware.
type Config struct {
	// JWT validation settings.
	JWTSecret   string // HMAC-SHA256 secret for JWT validation
	JWTIssuer   string // Required "iss" claim
	JWTAudience string // Required "aud" claim

	// PAT validation settings.
	PATAllowlist []string // Allowed personal access tokens
}

// Claims represents the validated JWT claims extracted from the token.
type Claims struct {
	Subject  string `json:"sub"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
}

// contextKey is an unexported type for context keys to avoid collisions.
type contextKey int

const claimsKey contextKey = 0

// ClaimsFromContext extracts validated claims from the request context.
// Returns nil if no claims are present (e.g., PAT-authenticated request).
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey).(*Claims)
	return c
}

// identityKey is the context key for the authenticated identity string.
const identityKey contextKey = 1

// IdentityFromContext extracts the authenticated identity from the request context.
// For JWT tokens this is the "sub" claim; for PATs this is "pat:<truncated>".
func IdentityFromContext(ctx context.Context) string {
	s, _ := ctx.Value(identityKey).(string)
	return s
}

// errorResponse is the JSON body returned on authentication failure.
type errorResponse struct {
	Error     string `json:"error"`
	ErrorCode string `json:"error_code"`
}

// Middleware returns an HTTP middleware that authenticates requests using
// bearer JWT tokens or personal access tokens (PATs).
//
// Token resolution order:
//  1. Extract bearer token from Authorization header
//  2. Try JWT validation (if JWTSecret is configured)
//  3. Try PAT validation (if PATAllowlist is configured)
//  4. Reject with HTTP 401 and error code "unauthorized"
func Middleware(cfg Config) func(http.Handler) http.Handler {
	patSet := make(map[string]bool, len(cfg.PATAllowlist))
	for _, pat := range cfg.PATAllowlist {
		if pat != "" {
			patSet[pat] = true
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := extractBearerToken(r)
			if !ok {
				writeUnauthorized(w, "missing or malformed Authorization header")
				return
			}

			// Try JWT validation first.
			if cfg.JWTSecret != "" {
				claims, err := validateJWT(token, cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience)
				if err == nil {
					ctx := context.WithValue(r.Context(), claimsKey, claims)
					ctx = context.WithValue(ctx, identityKey, claims.Subject)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// Try PAT validation.
			if len(patSet) > 0 && patSet[token] {
				identity := "pat:" + truncateToken(token)
				ctx := context.WithValue(r.Context(), identityKey, identity)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			writeUnauthorized(w, "invalid or expired token")
		})
	}
}

// extractBearerToken extracts the bearer token from the Authorization header.
// Returns the token and true if a valid bearer token is found.
func extractBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	// Must be "Bearer <token>" (case-insensitive prefix per RFC 6750).
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "bearer ") {
		return "", false
	}
	token := strings.TrimSpace(auth[7:])
	if token == "" {
		return "", false
	}
	return token, true
}

// validateJWT validates an HMAC-SHA256 (HS256) JWT token and returns claims.
func validateJWT(tokenStr, secret, requiredIssuer, requiredAudience string) (*Claims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT structure")
	}

	// Verify signature.
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT signature encoding: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(signature, expectedSig) {
		return nil, fmt.Errorf("invalid JWT signature")
	}

	// Verify header algorithm.
	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT header encoding: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("invalid JWT header: %w", err)
	}
	if header.Alg != "HS256" {
		return nil, fmt.Errorf("unsupported JWT algorithm: %s", header.Alg)
	}

	// Decode claims.
	claimsJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT claims encoding: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid JWT claims: %w", err)
	}

	// Check expiration.
	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("JWT expired")
	}

	// Check issuer.
	if requiredIssuer != "" && claims.Issuer != requiredIssuer {
		return nil, fmt.Errorf("JWT issuer mismatch: got %q, want %q", claims.Issuer, requiredIssuer)
	}

	// Check audience.
	if requiredAudience != "" && claims.Audience != requiredAudience {
		return nil, fmt.Errorf("JWT audience mismatch: got %q, want %q", claims.Audience, requiredAudience)
	}

	return &claims, nil
}

// base64URLDecode decodes a base64url-encoded string (no padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if necessary.
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// truncateToken returns the first 8 characters of a token for logging identity.
func truncateToken(token string) string {
	if len(token) <= 8 {
		return token
	}
	return token[:8]
}

// writeUnauthorized writes an HTTP 401 response with the "unauthorized" error code.
func writeUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(errorResponse{
		Error:     message,
		ErrorCode: "unauthorized",
	})
}
