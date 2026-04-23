// Package static implements the "static" Claims Mapping plugin, which
// matches URIs using regular expressions to generate claims using string
// templates.
//
// The plugin is authentication-agnostic. It reads only the
// ClientIdentity's URI and makes no assumption about the underlying
// authentication method — any URI is a valid input. Operators encode whatever
// structure they want extracted via named regex captures.
//
// Claim values are Go text/template strings. The following context is available
// during template evaluation:
//
//	.URIMatch  map[string]string of named regex captures
//	.Identity  the ClientIdentity interface (use .Identity.URI)
//
// Template rendering uses Option("missingkey=error"); thus, a typo in a
// template expression referencing a context variable produces a request-time error.
package static

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/messier-42/khaled/pkg/plugin/claimsmapping"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

// PrincipalConfig is a single entry in the static mapper's principal
// list. The regex in URI is anchored to the full URI string at
// compile time; one does not need to write ^...$ themselves.
type PrincipalConfig struct {
	// URI is a regular expression matched (fully) against the
	// authenticated ClientIdentity's URI. Named captures
	// (`(?P<name>...)`) are available to claim templates as
	// `.URIMatch.<name>`.
	URI string

	// Claims is a map from claim keys to Go text/template source.
	// Templates render against a context carrying URIMatch (named
	// captures) and Identity (the ClientIdentity).
	Claims map[string]string
}

// Mapper is the static ClaimsMapper.
type Mapper struct {
	entries []compiledEntry
}

type compiledEntry struct {
	pattern *regexp.Regexp
	names   []string
	claims  []compiledClaim
}

type compiledClaim struct {
	key  string
	tmpl *template.Template
}

var _ claimsmapping.ClaimsMapper = &Mapper{}

// New builds a Mapper from the ordered list of principal entries.
// Regex compilation, anchoring, and template parsing happen during construction:
// most malformed regex or template inputs result in New returning an error
// up front.
func New(principals []PrincipalConfig) (*Mapper, error) {
	if len(principals) == 0 {
		return nil, errors.New("static: at least one principal entry is required")
	}

	entries := make([]compiledEntry, 0, len(principals))
	for i, p := range principals {
		if strings.TrimSpace(p.URI) == "" {
			return nil, fmt.Errorf("static: principals[%d]: uri is required", i)
		}

		// Anchor the regex to the full URI. Wrapping in a
		// non-capturing group before anchoring is robust against
		// operator-supplied patterns that already start with ^, end
		// with \$ (literal dollar), or contain inline flags like
		// (?i).
		re, err := regexp.Compile("^(?:" + p.URI + ")$")
		if err != nil {
			return nil, fmt.Errorf("static: principals[%d]: compile uri regex %q: %w", i, p.URI, err)
		}

		// Probe context: a map populated with every named capture
		// this regex declares. Running each claim template against
		// it at construction time catches missing key errors
		// (template references to .URIMatch.unknown, etc.) as configuration
		// bugs rather than letting them surface as per-request
		// ErrPrincipalUnknown (403) once traffic starts.
		probeMatch := make(map[string]string, len(re.SubexpNames()))
		for _, name := range re.SubexpNames() {
			if name == "" {
				continue
			}
			probeMatch[name] = ""
		}
		probeCtx := staticTemplateContext{URIMatch: probeMatch, Identity: probeIdentity{}}

		claims := make([]compiledClaim, 0, len(p.Claims))
		for k, v := range p.Claims {
			t, err := template.New(fmt.Sprintf("principals[%d].claims[%s]", i, k)).
				Option("missingkey=error").
				Parse(v)
			if err != nil {
				return nil, fmt.Errorf("static: principals[%d]: parse claim %q template: %w", i, k, err)
			}
			if err := t.Execute(&bytes.Buffer{}, probeCtx); err != nil {
				return nil, fmt.Errorf("static: principals[%d]: claim %q references unknown field: %w", i, k, err)
			}
			claims = append(claims, compiledClaim{key: k, tmpl: t})
		}

		entries = append(entries, compiledEntry{
			pattern: re,
			names:   re.SubexpNames(),
			claims:  claims,
		})
	}

	return &Mapper{entries: entries}, nil
}

// probeIdentity is a minimal ClientIdentity used at construction
// time to let claim templates type-check their .Identity references.
type probeIdentity struct{}

func (probeIdentity) URI() string { return "" }

func (m *Mapper) Close() error {
	return nil
}

// Map evaluates the compiled entries in order. The first whose URI
// regex matches id.URI() is used to render the claim templates and
// produce a Principal. No match returns ErrPrincipalUnknown.
func (m *Mapper) Map(_ context.Context, id clientauthn.ClientIdentity) (policyengine.Principal, error) {
	if id == nil {
		return policyengine.Principal{}, fmt.Errorf("%w: nil identity", claimsmapping.ErrIdentityUnsupported)
	}
	uri := id.URI()

	for _, e := range m.entries {
		match := e.pattern.FindStringSubmatch(uri)
		if match == nil {
			continue
		}

		tmplCtx := staticTemplateContext{
			URIMatch: extractNamedCaptures(e.names, match),
			Identity: id,
		}

		claims := make(map[string]any, len(e.claims))
		for _, c := range e.claims {
			var buf bytes.Buffer
			if err := c.tmpl.Execute(&buf, tmplCtx); err != nil {
				return policyengine.Principal{}, fmt.Errorf("%w: render claim %q: %w", claimsmapping.ErrPrincipalUnknown, c.key, err)
			}
			claims[c.key] = buf.String()
		}

		return policyengine.Principal{URI: uri, Claims: claims}, nil
	}

	return policyengine.Principal{}, fmt.Errorf("%w: uri %q", claimsmapping.ErrPrincipalUnknown, uri)
}

// staticTemplateContext is the top-level value passed to claim
// templates.
type staticTemplateContext struct {
	// URIMatch holds named regex captures. Unnamed groups are not
	// exposed.
	URIMatch map[string]string

	// Identity is the ClientIdentity interface. Templates can use
	// {{.Identity.URI}}.
	Identity clientauthn.ClientIdentity
}

// extractNamedCaptures turns a regexp FindStringSubmatch result into
// a {name: value} map, skipping the whole-match at index 0 and any
// unnamed subexpressions.
func extractNamedCaptures(names []string, match []string) map[string]string {
	out := map[string]string{}
	for i, name := range names {
		if i == 0 || name == "" {
			continue
		}
		out[name] = match[i]
	}
	return out
}
