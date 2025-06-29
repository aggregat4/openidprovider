package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
)

// sendOauthAccessTokenErrorChi sends OAuth access token errors for Chi handlers
func sendOauthAccessTokenErrorChi(w http.ResponseWriter, errorCode string) {
	errorResponse := map[string]string{
		"error": errorCode,
	}
	jsonResponse(w, http.StatusBadRequest, errorResponse)
}

// sendInternalErrorChi sends internal errors for Chi handlers
func sendInternalErrorChi(w http.ResponseWriter, r *http.Request, originalError error, fullRedirectUri *url.URL, state string) {
	slog.Error("Internal error", "error", originalError)
	sendOauthErrorChi(w, r, fullRedirectUri, "server_error", "Internal server error", state)
}

// sendOauthErrorChi sends OAuth errors for Chi handlers
func sendOauthErrorChi(w http.ResponseWriter, r *http.Request, redirectUri *url.URL, errorCode string, description string, state string) {
	if redirectUri != nil {
		q := redirectUri.Query()
		q.Set("error", errorCode)
		if description != "" {
			q.Set("error_description", description)
		}
		if state != "" {
			q.Set("state", state)
		}
		redirectUri.RawQuery = q.Encode()
		redirectResponse(w, r, http.StatusFound, redirectUri.String())
	} else {
		stringResponse(w, http.StatusBadRequest, "OAuth error: "+errorCode)
	}
}

// redirectResponse sends a redirect response
func redirectResponse(w http.ResponseWriter, r *http.Request, statusCode int, url string) {
	http.Redirect(w, r, url, statusCode)
}

// jsonResponse sends a JSON response
func jsonResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", ContentTypeJson)
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Failed to encode JSON response", "error", err)
	}
}

// stringResponse sends a plain text response
func stringResponse(w http.ResponseWriter, statusCode int, data string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(statusCode)
	w.Write([]byte(data))
}

// getParamChi extracts a parameter from URL path, query string, or form data
func getParamChi(r *http.Request, paramName string) string {
	// Try URL parameter first (Chi path parameters)
	if param := chi.URLParam(r, paramName); param != "" {
		return param
	}

	// Try query parameter
	if param := r.URL.Query().Get(paramName); param != "" {
		return param
	}

	// Try form value
	if err := r.ParseForm(); err == nil {
		if param := r.FormValue(paramName); param != "" {
			return param
		}
	}

	return ""
}

// getFormValueChi safely gets a form value after parsing the form
func getFormValueChi(r *http.Request, key string) string {
	if err := r.ParseForm(); err != nil {
		return ""
	}
	return r.FormValue(key)
}
