package router

import (
	"net/http"
	"strings"
)

// RedirectAll answers every request with a permanent redirect to the same
// path and query on target. It is the retirement mode for a deployment that
// moved to a new domain (REDIRECT_ALL_TO): browsers land on the new origin,
// and API clients get an unambiguous signal to reconfigure.
func RedirectAll(target string) http.Handler {
	base := strings.TrimRight(target, "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, base+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}
