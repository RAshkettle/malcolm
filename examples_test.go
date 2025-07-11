package malcolm

import (
	"fmt"
	"log/slog"
	"net/http"
)

func ExampleNewMiddleWare() {
	logger := slog.New(slog.NewJSONHandler(nil, nil))
	m := NewMiddleWare(logger)

	if m.logger == nil {
		fmt.Println("logger is nil")
	}
}

func ExampleNoSurf() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	// To use the NoSurf middleware, you can wrap your handler with it.
	http.ListenAndServe(":8080", NoSurf(mux))
}

func ExampleCommonHeaders() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	// To use the CommonHeaders middleware, you can wrap your handler with it.
	http.ListenAndServe(":8080", CommonHeaders(mux))
}

func ExampleMiddleWare_RecoverPanic() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	m := NewMiddleWare(nil)

	// To use the RecoverPanic middleware, you can wrap your handler with it.
	http.ListenAndServe(":8080", m.RecoverPanic(mux))
}

func ExampleMiddleWare_ServerError() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		m := NewMiddleWare(nil)
		m.ServerError(w, r, fmt.Errorf("test error"))
	})

	http.ListenAndServe(":8080", mux)
}

func ExampleClientError() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ClientError(w, http.StatusNotFound)
	})

	http.ListenAndServe(":8080", mux)
}
