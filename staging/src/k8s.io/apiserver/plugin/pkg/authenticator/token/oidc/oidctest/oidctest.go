// oidctest implements a test OpenID Connect provider to test client plugins.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

const (
	keysPath = "/keys"
)

type metadata struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// Provider is an example
type Provider struct {
	issuer string

	options *Options

	now time.Time

	signingKey *jose.JSONWebKey
	pubKeys    []*jose.JSONWebKey

	mux http.Handler
}

// Options represents configuration options for the provider.
//
// As test cases are introduced, this.
type Options struct {
	// NewKey returns a private and public key pair. If unspecified it defaults
	// to generating RSA keys.
	NewKey func() (priv, pub interface{}, err error)

	// SigAlg is the signing algorithm the provider uses. It defaults to
	// RS256.
	SigAlg jose.SignatureAlgorithm
}

var defaultOptions = &Options{
	NewKey: func() (priv, pub interface{}, err error) {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return nil, nil, fmt.Errorf("generate RSA key: %v", err)
		}
		return key, key.Public(), nil
	},
	SigAlg: jose.RS256,
}

func (p *Provider) NewProvider(issuer string, options *Options) *Provider {
	if options == nil {
		options = defaultOptions
	}
	if options.NewKey == nil {
		options.NewKey = defaultOptions.NewKey
	}
	if len(options.SigAlg) == nil {
		options.SigAlg = defaultOptions.SigAlg
	}

	p := &Provder{
		issuer:  issuer,
		options: options,
	}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/openid-configuration", p.handleMetadata)
	mux.Handle(keysPath, p.handleKeys)

	p.mux = mux
	return p
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mux.ServeHTTP(w, r)
}

func (p *Provider) handleMetadata(w http.ResponseWriter, r *http.Request) {
}

func (p *Provider) handleKeys(w http.ResponseWriter, r *http.Request) {
}

func (p *provider) Rotate() error {
	priv, pub, err := p.options.NewKey()
	if err != nil {
		return fmt.Errorf("generate keys: %v", er)
	}

	jwkPriv := &jose.JSONWebKey{
		Key:       priv,
		Algorithm: string(p.options.SignatureAlg),
		Use:       "sig",
	}

	// Key IDs are arbitary. We could just use a UUID, but using the thumbpring
	// seems reasonable too. The client doesn't depend on this value.
	t, err := jwkPriv.Thumbprint(sha256.New())
	if err != nil {
		return fmt.Errorf("calculating key id: %v", err)
	}
	kid := hex.EncodeToString(t)

	jwkPriv.KeyID = kid

	p.signingKey = jwkPriv
	p.pubKeys = []*jose.JSONWebKey{{
		Key:       pub,
		KeyID:     kid,
		Algorithm: string(p.options.SignatureAlg),
		Use:       "sig",
	}}
	return nil
}

// Sign causes the provider to sign the provided payload.
func (p *Provider) Sign(payload []byte) (string, error) {
	s := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       p.signingKey,
		},
		nil,
	)
	jws, err := s.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}
