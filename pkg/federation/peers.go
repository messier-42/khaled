package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckapclient"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/messier-42/cabe-go/coserecipient"
)

// Peer specifies exactly one provisioned public identity or discovery URL.
// DomainID is independently configured and must match discovered identities.
type Peer struct {
	DomainID string
	Identity *ckapraw.FederationIdentity
	URL      string
	CAFile   string
}
type peerState struct {
	config Peer
	client *ckapclient.Client
	// gate serializes cache access and refreshes while allowing each waiter
	// to cancel independently of the in-flight discovery request.
	gate     chan struct{}
	identity *ckapraw.FederationIdentity
	until    time.Time
}

func newPeer(p Peer) (*peerState, error) {
	if p.DomainID == "" || (p.Identity == nil) == (p.URL == "") {
		return nil, errors.New("federation: peer requires domainID and exactly one identity or URL")
	}
	s := &peerState{config: p, gate: make(chan struct{}, 1)}
	if p.Identity != nil {
		if p.CAFile != "" {
			return nil, errors.New("federation: caFile requires discovery")
		}
		raw, err := key.MarshalCBOR(p.Identity)
		if err != nil {
			return nil, err
		}
		var copied ckapraw.FederationIdentity
		if err = key.UnmarshalCBOR(raw, &copied); err != nil {
			return nil, err
		}
		if err = validateIdentity(p.DomainID, &copied); err != nil {
			return nil, err
		}
		s.identity = &copied
	} else {
		u, err := url.Parse(p.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
			return nil, errors.New("federation: discovery requires an HTTPS base URL")
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		if p.CAFile != "" {
			raw, err := os.ReadFile(p.CAFile)
			if err != nil {
				return nil, err
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(raw) {
				return nil, errors.New("federation: invalid discovery CA")
			}
			transport.TLSClientConfig.RootCAs = roots
		}
		// Discovery is sporadic. Avoid retained idle transports on runtime reload.
		transport.DisableKeepAlives = true
		s.client, err = ckapclient.NewClient(ckapclient.Config{BaseURL: p.URL, HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("federation: discovery redirects disabled")
		}}})
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}
func validateIdentity(expected string, id *ckapraw.FederationIdentity) error {
	if _, err := id.ToCABE(); err != nil {
		return err
	}
	if id.DomainID != expected {
		return errors.New("federation: peer Domain ID mismatch")
	}
	seen := map[string]bool{}
	for _, p := range id.Keys {
		if !publicOnly(p.PublicKey) {
			return errors.New("federation: private peer key")
		}
		kid := string(p.PublicKey.Kid())
		if seen[kid] {
			return errors.New("federation: duplicate peer FKID")
		}
		seen[kid] = true
	}
	return nil
}
func usableNIST(k key.Key) bool {
	kty, err := k.GetInt(iana.KeyParameterKty)
	if err != nil || kty != iana.KeyTypeEC2 {
		return false
	}
	crv, err := k.GetInt(iana.EC2KeyParameterCrv)
	if err != nil || (crv != iana.EllipticCurveP_256 && crv != iana.EllipticCurveP_384 && crv != iana.EllipticCurveP_521) {
		return false
	}
	alg, err := k.GetInt(iana.KeyParameterAlg)
	if err != nil || (alg != iana.AlgorithmECDH_ES_A128KW && alg != iana.AlgorithmECDH_ES_A192KW && alg != iana.AlgorithmECDH_ES_A256KW) {
		return false
	}
	// Delegate key-operations and point validation to the library implementation.
	_, err = coserecipient.WrapKey(k, make([]byte, 32), coserecipient.Context{})
	return err == nil
}
func (p *peerState) recipients(ctx context.Context, now time.Time) ([]key.Key, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// Cancellation and gate availability can become ready together. Check
	// again before returning cached keys or starting a refresh.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.client != nil && (p.identity == nil || !now.Before(p.until)) {
		got, err := p.client.FederationIdentity(ctx, ckap.FederationIdentityRequest{})
		if err != nil {
			return nil, err
		}
		id := ckapraw.FederationIdentity{Kind: ckapraw.KindFederationIdentity, DomainID: got.Identity.DomainID, Keys: []ckapraw.FederationPublicKey{}}
		for _, k := range got.Identity.Keys {
			var pub key.Key
			if err = key.UnmarshalCBOR(k.RawCOSEKey, &pub); err != nil {
				return nil, err
			}
			id.Keys = append(id.Keys, ckapraw.FederationPublicKey{PublicKey: pub, Status: k.Status})
		}
		if err = validateIdentity(p.config.DomainID, &id); err != nil {
			return nil, err
		}
		p.identity = &id
		p.until = freshUntil(now, got.CacheControl, got.Expires)
	}
	for _, status := range []string{"current", "future", "retired"} {
		var out []key.Key
		for _, k := range p.identity.Keys {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if k.Status == status && usableNIST(k.PublicKey) {
				out = append(out, k.PublicKey)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	return nil, fmt.Errorf("federation: peer %q has no usable NIST key", p.config.DomainID)
}

// freshUntil is deliberately conservative: invalid/ambiguous freshness forces
// revalidation, and an absolute expiry caps max-age so intermediary age cannot
// extend a published rollover deadline.
func freshUntil(now time.Time, control, expires string) time.Time {
	until := now
	expiry, expiryErr := http.ParseTime(expires)
	if expiryErr == nil {
		until = expiry
	}
	seenMaxAge := false
	for part := range strings.SplitSeq(control, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch strings.ToLower(name) {
		case "no-cache", "no-store":
			return now
		case "max-age":
			if seenMaxAge {
				return now
			}
			seenMaxAge = true
			n, err := strconv.ParseInt(strings.Trim(value, "\""), 10, 64)
			if err != nil || n < 0 || n > 86400*365 {
				return now
			}
			until = now.Add(time.Duration(n) * time.Second)
		}
	}
	if expiryErr == nil && expiry.Before(until) {
		until = expiry
	}
	if until.Before(now) {
		return now
	}
	return until
}

func publicOnly(k key.Key) bool {
	kty, err := k.GetInt(iana.KeyParameterKty)
	if err != nil {
		return false
	}
	switch kty {
	case iana.KeyTypeEC2, iana.KeyTypeOKP:
		return !k.Has(-4)
	case iana.KeyTypeRSA:
		for label := -3; label >= -12; label-- {
			if k.Has(label) {
				return false
			}
		}
		return true
	default:
		return false // symmetric or unknown representations cannot be verified public
	}
}
