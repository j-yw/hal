package deploy

import (
	"encoding/json"
	"net/http"
)

// HealthResponse is the JSON body returned by the control-plane health endpoint.
type HealthResponse struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
	Adapter string `json:"adapter"`
}

// HealthHandler returns an http.HandlerFunc that responds with HTTP 200 and
// a JSON health payload. It is unauthenticated so external monitors can probe it.
func HealthHandler(version, adapter string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(HealthResponse{
			OK:      true,
			Version: version,
			Adapter: adapter,
		})
	}
}
