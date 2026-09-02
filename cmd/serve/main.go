//go:build !js

// Command serve is a local static file server for developing the dashboard.
//
// It exists for one reason: Go's WebAssembly loader uses
// WebAssembly.instantiateStreaming, which requires the server to send
// Content-Type: application/wasm. Several common static servers (including
// Python's http.server) send application/octet-stream instead, which silently
// falls back to a slower path or fails outright.
//
// This is a development tool only. GitHub Pages serves .wasm correctly in
// production, so nothing here ships.
package main

import (
	"flag"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	dir := flag.String("dir", "web", "directory to serve")
	addr := flag.String("addr", ":8787", "listen address")
	flag.Parse()

	if err := mime.AddExtensionType(".wasm", "application/wasm"); err != nil {
		log.Fatalf("register wasm mime type: %v", err)
	}

	abs, err := filepath.Abs(*dir)
	if err != nil {
		log.Fatalf("resolve %s: %v", *dir, err)
	}
	if _, err := os.Stat(abs); err != nil {
		log.Fatalf("serve directory: %v", err)
	}

	fs := http.FileServer(http.Dir(abs))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mirror the production security headers so anything that would break
		// under them breaks here first, not after deployment.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Cache-Control", "no-store")
		fs.ServeHTTP(w, r)
	})

	log.Printf("crossfault dev server → http://localhost%s (serving %s)", *addr, abs)
	if err := http.ListenAndServe(*addr, handler); err != nil {
		log.Fatal(err)
	}
}
