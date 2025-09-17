package server

import (
	"aggregat4/openidprovider/internal/logging"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
)

// sendOauthAccessTokenError sends OAuth access token errors
func sendOauthAccessTokenError(w http.ResponseWriter, errorCode string) {
	errorResponse := map[string]string{
		"error": errorCode,
	}
	jsonResponse(w, http.StatusBadRequest, errorResponse)
}

// sendInternalOAuthError sends internal errors
func sendInternalOAuthError(w http.ResponseWriter, r *http.Request, originalError error, fullRedirectUri *url.URL, state string) {
	logging.Error(logger, "Internal error: %v", originalError)
	sendOauthError(w, r, fullRedirectUri, "server_error", "Internal server error", state)
}

// sendOauthError sends OAuth errors
func sendOauthError(w http.ResponseWriter, r *http.Request, redirectUri *url.URL, errorCode string, description string, state string) {
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
func jsonResponse(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", ContentTypeJson)
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logging.Error(logger, "Failed to encode JSON response: %v", err)
	}
}

// stringResponse sends a plain text response
func stringResponse(w http.ResponseWriter, statusCode int, data string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(statusCode)
	w.Write([]byte(data))
}

// getParam extracts a parameter from URL path, query string, or form data
func getParam(r *http.Request, paramName string) string {
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

// getFormValue safely gets a form value after parsing the form
func getFormValue(r *http.Request, key string) string {
	if err := r.ParseForm(); err != nil {
		return ""
	}
	return r.FormValue(key)
}
