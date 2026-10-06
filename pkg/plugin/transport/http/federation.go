package http

import (
	"fmt"
	stdhttp "net/http"
	"time"

	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/khaled/pkg/keyserver"
)

func federationIdentityHandler(get func() *keyserver.Server) stdhttp.Handler {
	return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if err := expectCKAPMediaType(r.Header.Get("Accept"), "Accept"); err != nil {
			writeCKAPError(r.Context(), w, stdhttp.StatusBadRequest, cabe.CodeMalformedRequest, err.Error())
			return
		}
		if get == nil {
			stdhttp.NotFound(w, r)
			return
		}
		s := get()
		if s == nil {
			writeCKAPError(r.Context(), w, stdhttp.StatusServiceUnavailable, cabe.CodeInternal, "service unavailable")
			return
		}
		id, until, err := s.FederationIdentity(r.Context())
		if err != nil {
			writeMappedError(w, r.Context(), err)
			return
		}
		if id == nil {
			stdhttp.NotFound(w, r)
			return
		}
		now := time.Now().UTC()
		seconds := max(int64(until.Sub(now)/time.Second), 0)
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, must-revalidate", seconds))
		w.Header().Set("Expires", now.Add(time.Duration(seconds)*time.Second).Format(stdhttp.TimeFormat))
		writeCKAPResponse(w, r.Context(), stdhttp.StatusOK, id)
	})
}
