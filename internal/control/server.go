package control

import (
	"encoding/json"
	"errors"
	"net/http"
)

func NewHandler(service *Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}

		writeJSON(w, http.StatusOK, service.Status())
	})
	mux.HandleFunc("/v1/validate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodPost, http.MethodGet)
			return
		}

		scope := ScopePermanent
		if raw := r.URL.Query().Get("scope"); raw != "" {
			parsed, err := ParseScope(raw)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
				return
			}
			scope = parsed
		}

		resp := service.Validate(scope)
		writeJSON(w, http.StatusOK, resp)
	})
	mux.HandleFunc("/v1/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		resp, err := service.Reload()
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, struct {
				ErrorResponse
				ReloadResponse
			}{
				ErrorResponse:  ErrorResponse{Error: err.Error()},
				ReloadResponse: resp,
			})
			return
		}

		writeJSON(w, http.StatusOK, resp)
	})
	mux.HandleFunc("/v1/runtime/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		var req ApplyRuntimeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
			return
		}

		resp, err := service.ApplyRuntime(req.Ruleset)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, struct {
				ErrorResponse
				ApplyResponse
			}{
				ErrorResponse: ErrorResponse{Error: err.Error()},
				ApplyResponse: resp,
			})
			return
		}

		writeJSON(w, http.StatusOK, resp)
	})
	mux.HandleFunc("/v1/runtime/save", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		resp, err := service.SaveRuntime()
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, struct {
				ErrorResponse
				SaveResponse
			}{
				ErrorResponse: ErrorResponse{Error: err.Error()},
				SaveResponse:  resp,
			})
			return
		}

		writeJSON(w, http.StatusOK, resp)
	})

	return mux
}

func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeMethodNotAllowed(w http.ResponseWriter, methods ...string) {
	for _, method := range methods {
		w.Header().Add("Allow", method)
	}
	writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: errors.New("method not allowed").Error()})
}
