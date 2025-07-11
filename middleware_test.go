package malcolm

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCommonHeaders(t *testing.T) {
	rr := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})
	CommonHeaders(next).ServeHTTP(rr, r)

	rs := rr.Result()

	// Check that the middleware has correctly set the Content-Security-Policy
	// header on the response.
	expectedValue := "default-src 'self'; style-src 'self' fonts.googleapis.com; font-src fonts.gstatic.com"
	Equal(t, rs.Header.Get("Content-Security-Policy"), expectedValue)

	// Check that the middleware has correctly set the Referrer-Policy
	// header on the response.
	expectedValue = "origin-when-cross-origin"

	Equal(t, rs.Header.Get("Referrer-Policy"), expectedValue)

	// Check that the middleware has correctly set the X-Content-Type-Options
	// header on the response.
	expectedValue = "nosniff"
	Equal(t, rs.Header.Get("X-Content-Type-Options"), expectedValue)

	// Check that the middleware has correctly set the X-Frame-Options header
	// on the response.
	expectedValue = "deny"
	Equal(t, rs.Header.Get("X-Frame-Options"), expectedValue)

	// Check that the middleware has correctly set the X-XSS-Protection header
	// on the response
	expectedValue = "0"
	Equal(t, rs.Header.Get("X-XSS-Protection"), expectedValue)

	// Check that the middleware has correctly set the Server header on the
	// response.
	expectedValue = "Go"
	Equal(t, rs.Header.Get("Server"), expectedValue)

	Equal(t, rs.StatusCode, http.StatusOK)

	defer rs.Body.Close()
	body, err := io.ReadAll(rs.Body)
	if err != nil {
		t.Fatal(err)
	}
	body = bytes.TrimSpace(body)

	Equal(t, string(body), "OK")
}

func Equal[T comparable](t *testing.T, actual, expected T) {
	t.Helper()

	if actual != expected {
		t.Errorf("got: %v; want: %v", actual, expected)
	}
}

func TestRecoverPanic(t *testing.T) {
	t.Run("it does not panic", func(t *testing.T) {
		rr := httptest.NewRecorder()

		r, err := http.NewRequest(http.MethodGet, "/", nil)
		if err != nil {
			t.Fatal(err)
		}

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		})

		m := NewMiddleWare(nil)
		m.RecoverPanic(next).ServeHTTP(rr, r)

		rs := rr.Result()

		Equal(t, rs.StatusCode, http.StatusOK)

		defer rs.Body.Close()
		body, err := io.ReadAll(rs.Body)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.TrimSpace(body)

		Equal(t, string(body), "OK")
	})

	t.Run("it panics", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		rr := httptest.NewRecorder()

		r, err := http.NewRequest(http.MethodGet, "/", nil)
		if err != nil {
			t.Fatal(err)
		}

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		})

		m := NewMiddleWare(logger)
		m.RecoverPanic(next).ServeHTTP(rr, r)

		rs := rr.Result()

		Equal(t, rs.StatusCode, http.StatusInternalServerError)

		if buf.String() == "" {
			t.Error("expected log to not be empty")
		}
	})
}

func TestServerError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	rr := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	m := NewMiddleWare(logger)
	m.ServerError(rr, r, fmt.Errorf("test error"))

	rs := rr.Result()

	Equal(t, rs.StatusCode, http.StatusInternalServerError)

	if buf.String() == "" {
		t.Error("expected log to not be empty")
	}
}

func TestClientError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{
			name:       "not found",
			statusCode: http.StatusNotFound,
		},
		{
			name:       "bad request",
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "unauthorized",
			statusCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()

			ClientError(rr, tt.statusCode)

			rs := rr.Result()

			Equal(t, rs.StatusCode, tt.statusCode)
		})
	}
}

func TestNoSurf(t *testing.T) {
	rr := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	NoSurf(next).ServeHTTP(rr, r)

	rs := rr.Result()

	Equal(t, rs.StatusCode, http.StatusOK)

	// Check that the middleware has correctly set the CSRF cookie on the response.
	cookie := rs.Cookies()[0]
	Equal(t, cookie.Name, "csrf_token")
	Equal(t, cookie.HttpOnly, true)
	Equal(t, cookie.Secure, true)
	Equal(t, cookie.Path, "/")
}

func TestNewMiddleWare(t *testing.T) {
	t.Run("with a logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		m := NewMiddleWare(logger)

		if m.logger == nil {
			t.Error("expected logger to be initialized")
		}
	})

	t.Run("with a nil logger", func(t *testing.T) {
		m := NewMiddleWare(nil)

		if m.logger == nil {
			t.Error("expected logger to be initialized")
		}
	})
}

func BenchmarkCommonHeaders(b *testing.B) {
	rr := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		b.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		CommonHeaders(next).ServeHTTP(rr, r)
	}
}

func BenchmarkNoSurf(b *testing.B) {
	rr := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		b.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		NoSurf(next).ServeHTTP(rr, r)
	}
}

func BenchmarkRecoverPanic(b *testing.B) {
	rr := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		b.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	m := NewMiddleWare(nil)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.RecoverPanic(next).ServeHTTP(rr, r)
	}
}
