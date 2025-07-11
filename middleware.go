// Package malcolm contains middleware that is commonly used in go http servers
package malcolm

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"

	"github.com/justinas/nosurf"
)

type MiddleWare struct {
	logger *slog.Logger
}

func NewMiddleWare(logger *slog.Logger) *MiddleWare {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}

	return &MiddleWare{
		logger: logger,
	}
}

// NoSurf is a middleware that provides CSRF protection using the nosurf package.
func NoSurf(next http.Handler) http.Handler {
	csrfHandler := nosurf.New(next)
	csrfHandler.SetBaseCookie(http.Cookie{
		HttpOnly: true,
		Path:     "/",
		Secure:   true,
	})

	return csrfHandler
}

// CommonHeaders is a middleware that sets common security headers for all HTTP responses.
func CommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set Content Security Policy
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' fonts.googleapis.com; font-src fonts.gstatic.com")

		// Set Referrer Policy
		w.Header().Set("Referrer-Policy", "origin-when-cross-origin")
		// Set X-Content-Type-Options to prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Set X-Frame-Options to prevent clickjacking
		w.Header().Set("X-Frame-Options", "deny")
		// Disable X-XSS-Protection
		w.Header().Set("X-XSS-Protection", "0")
		// Set Server header
		w.Header().Set("Server", "Go")

		next.ServeHTTP(w, r)
	})
}

// RecoverPanic is a middleware that recovers from any panics and writes a 500 Internal Server Error response.
func (m *MiddleWare) RecoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.Header().Set("Connection", "close")
				m.ServerError(w, r, fmt.Errorf("%s", err))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ServerError is a middleware function that will log and return an error if it occurs on the server side.
func (m *MiddleWare) ServerError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		method = r.Method
		uri    = r.URL.RequestURI()
		trace  = string(debug.Stack())
	)

	m.logger.Error(err.Error(), "method", method, "uri", uri, "trace", trace)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

// ClientError is a middleware function that will return an error for actions on the client side.
func ClientError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}
