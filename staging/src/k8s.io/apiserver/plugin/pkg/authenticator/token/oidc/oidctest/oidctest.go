// oidctest implements a test OpenID Connect provider to test client plugins.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"

	jose "gopkg.in/square/go-jose.v2"
)

const (
	keysPath = "/keys"
	metaPath = "/.well-known/openid-configuration"
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

// Provider is test implementation of an OpenID Connect provider that only
// implements the keys endpoint.
type Provider struct {
	issuer string

	options *Options

	signingKey *jose.JSONWebKey
	pubKeys    *jose.JSONWebKeySet

	mux http.Handler
}

// Options represents configuration options for the provider.
//
// As test cases are introduced, this struct will expand.
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

// NewProvider returns a test implementation of an OpenID Connect provider.
func NewProvider(issuer string, options *Options) (*Provider, error) {
	if options == nil {
		options = defaultOptions
	}
	if options.NewKey == nil {
		options.NewKey = defaultOptions.NewKey
	}
	if len(options.SigAlg) == 0 {
		options.SigAlg = defaultOptions.SigAlg
	}

	priv, pub, err := options.NewKey()
	if err != nil {
		return nil, err
	}

	p := &Provider{
		issuer:  issuer,
		options: options,
		signingKey: &jose.JSONWebKey{
			Key:       priv,
			KeyID:     "foo",
			Algorithm: string(options.SigAlg),
			Use:       "sign",
		},
		pubKeys: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:       pub,
					KeyID:     "foo",
					Algorithm: string(options.SigAlg),
					Use:       "sign",
				},
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(metaPath, p.handleMetadata)
	mux.HandleFunc(keysPath, p.handleKeys)

	p.mux = mux
	return p, nil
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mux.ServeHTTP(w, r)
}

func (p *Provider) handleMetadata(w http.ResponseWriter, r *http.Request) {
	m := metadata{
		Issuer:  p.issuer,
		JwksURI: p.issuer + keysPath,

		// Not actually implemented.
		AuthorizationEndpoint: p.issuer + "/auth",
		TokenEndpoint:         p.issuer + "/token",

		ResponseTypesSupported: []string{"code"},
		SubjectTypesSupported:  []string{"public"},

		IDTokenSigningAlgValuesSupported: []string{
			string(p.options.SigAlg),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m)
}

func (p *Provider) handleKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p.pubKeys)
}

// Sign causes the provider to sign the provided payload.
func (p *Provider) Sign(payload []byte) (string, error) {
	s, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: p.options.SigAlg,
			Key:       p.signingKey,
		},
		nil,
	)
	if err != nil {
		return "", err
	}
	jws, err := s.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}
