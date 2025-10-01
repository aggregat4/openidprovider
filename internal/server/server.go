package server

import (
	"aggregat4/openidprovider/internal/cleanup"
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/logging"
	"aggregat4/openidprovider/internal/repository"
	"aggregat4/openidprovider/pkg/email"
	"context"
	"crypto/subtle"
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	baselibmiddleware "github.com/aggregat4/go-baselib-services/v3/middleware"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

// Context key types to avoid string collisions
type contextKey string

const (
	sessionContextKey  contextKey = "session"
	clientIDContextKey contextKey = "client_id"
)

type Controller struct {
	Store           *repository.Store
	Config          domain.Configuration
	EmailService    email.EmailSender
	CleanupJob      *cleanup.CleanupJob
	CaptchaVerifier CaptchaVerifier
}

var logger = logging.ForComponent("server")

const ContentTypeJson = "application/json;charset=UTF-8"

//go:embed views/*.html
var viewFiles embed.FS

//go:embed public/styles/*.css
var styles embed.FS

//go:embed public/scripts/*.js
var scripts embed.FS

// RunServer starts the Chi-based server
func RunServer(controller Controller) {
	router := InitServer(controller)

	server := &http.Server{
		Addr:         ":" + strconv.Itoa(controller.Config.ServerPort),
		Handler:      router,
		ReadTimeout:  time.Duration(controller.Config.ServerReadTimeoutSeconds) * time.Second,
		WriteTimeout: time.Duration(controller.Config.ServerWriteTimeoutSeconds) * time.Second,
	}

	logger.Info("Server starting on port {Port}", controller.Config.ServerPort)
	if err := server.ListenAndServe(); err != nil {
		logger.Error("Server failed to start {Error}", err)
		os.Exit(1)
	}
}

// InitServer initializes the Chi router with all routes and middleware
func InitServer(controller Controller) *chi.Mux {
	r := chi.NewRouter()

	// Start cleanup job
	controller.CleanupJob = cleanup.NewCleanupJob(controller.Store, controller.Config.CleanupConfig)
	controller.CleanupJob.Start()

	sessionStore := sessions.NewCookieStore([]byte(uuid.New().String()))

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(loggingMiddleware)
	r.Use(CreateSessionMiddleware(sessionStore))
	r.Use(middleware.Compress(5))
	r.Use(controller.basicAuthMiddleware)
	r.Use(baselibmiddleware.CreateCsrfMiddlewareWithSkipperStd(func(r *http.Request) bool {
		return r.URL.Path == "/token"
	}))

	// Static files
	stylesServer := http.FileServer(http.FS(styles))
	r.Handle("/public/styles/*", stylesServer)
	scriptsServer := http.FileServer(http.FS(scripts))
	r.Handle("/public/scripts/*", scriptsServer)

	// Routes
	r.Get("/", controller.LandingPageHandler)
	r.Get("/status", controller.StatusHandler)

	r.Get("/.well-known/openid-configuration", controller.OpenIdConfigurationHandler)
	r.Get("/.well-known/jwks.json", controller.JwksHandler)

	r.Get("/authorize", controller.AuthorizeHandler)
	r.Post("/authorize", controller.AuthorizeHandler)

	r.Get("/login", controller.LoginHandler)
	r.Post("/login", controller.LoginHandler)

	r.Post("/token", controller.TokenHandler)

	r.Get("/register", controller.ShowRegisterPageHandler)
	r.Post("/register", controller.RegisterHandler)

	r.Get("/verify", controller.ShowVerificationPageHandler)
	r.Post("/verify", controller.VerifyHandler)

	r.Get("/forgot-password", controller.ShowForgotPasswordPageHandler)
	r.Post("/forgot-password", controller.ForgotPasswordHandler)
	r.Get("/reset-password", controller.ShowResetPasswordPageHandler)
	r.Post("/reset-password", controller.ResetPasswordHandler)

	r.Get("/delete-account", controller.ShowDeleteAccountPageHandler)
	r.Post("/delete-account", controller.DeleteAccountHandler)
	r.Get("/verify-delete", controller.ShowVerifyDeletePageHandler)
	r.Post("/verify-delete", controller.VerifyDeleteHandler)
	r.Get("/verify-delete/resend", controller.ResendDeleteVerificationHandler)

	return r
}

// renderTemplate renders an HTML template
func (controller *Controller) renderTemplate(w http.ResponseWriter, templateName string, data any, statusCode int) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	tmpl := template.Must(template.New("").ParseFS(viewFiles, "views/*.html"))
	// Use base name without .html extension for execution
	baseName := templateName
	if strings.HasSuffix(templateName, ".html") {
		baseName = strings.TrimSuffix(templateName, ".html")
	}
	err := tmpl.ExecuteTemplate(w, baseName, data)
	if err != nil {
		logger.Error("Template execution failed {TemplateName} {Error}", baseName, err)
		return err
	}
	return nil
}

// loggingMiddleware logs all requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// // Log form data for POST requests
		// if r.Method == http.MethodPost {
		// 	if err := r.ParseForm(); err == nil {
		// 		logging.Info(logger, "Parsed form data form={Form}", r.Form.Encode())
		// 	}
		// }

		// Create a response writer wrapper to capture status
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		logging.Info(logger, "Request completed method={Method} path={Path} status={Status} bytesWritten={BytesWritten}",
			r.Method,
			r.URL.Path,
			ww.Status(),
			ww.BytesWritten(),
		)
	})
}

func CreateSessionMiddleware(sessionStore *sessions.CookieStore) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := sessionStore.Get(r, "session")
			if err != nil {
				logger.Error("Failed to get session {Error}", err)
			}

			// Add session to request context
			ctx := context.WithValue(r.Context(), sessionContextKey, session)
			next.ServeHTTP(w, r.WithContext(ctx))

			// Save session if modified
			if session.IsNew {
				session.Save(r, w)
			}
		})
	}
}

// basicAuthMiddleware adds basic authentication for token endpoint
func (controller *Controller) basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip basic auth for non-token endpoints
		if r.URL.Path != "/token" {
			next.ServeHTTP(w, r)
			return
		}

		username, password, basicAuthOk := r.BasicAuth()
		client, clientExists := controller.Config.RegisteredClients[domain.ClientId(username)]

		decodedUsername, err := url.QueryUnescape(username)
		if err != nil {
			decodedUsername = ""
		}
		decodedPassword, err := url.QueryUnescape(password)
		if err != nil {
			decodedPassword = ""
		}

		if !clientExists || !basicAuthOk {
			// make sure we nevertheless compare the username and password to make timing attacks harder
			subtle.ConstantTimeCompare([]byte(decodedUsername), []byte("this is not a valid client id"))
			subtle.ConstantTimeCompare([]byte(decodedPassword), []byte("this is not a valid client secret"))
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if subtle.ConstantTimeCompare([]byte(decodedUsername), []byte(client.Id)) == 1 &&
			subtle.ConstantTimeCompare([]byte(decodedPassword), []byte(client.BasicAuthSecret)) == 1 {
			// Add client_id to request context to indicate that the client is authenticated
			ctx := context.WithValue(r.Context(), clientIDContextKey, username)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		} else {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	})
}
