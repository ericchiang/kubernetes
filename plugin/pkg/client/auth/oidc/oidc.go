/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"

	"github.com/ericchiang/oidc"
	"github.com/golang/glog"

	"k8s.io/kubernetes/pkg/client/restclient"
	"k8s.io/kubernetes/pkg/util/wait"
)

// expiryDelta determines how earlier a token should be considered
// expired than its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
//
// NOTE(ericchiang): This is taken from golang.org/x/oauth2 to try to
// match its behavor, though no logic depends on it being identical.
const expiryDelta = 10 * time.Second

const (
	cfgIssuerUrl                = "idp-issuer-url"
	cfgClientID                 = "client-id"
	cfgClientSecret             = "client-secret"
	cfgCertificateAuthority     = "idp-certificate-authority"
	cfgCertificateAuthorityData = "idp-certificate-authority-data"
	cfgExtraScopes              = "extra-scopes"
	cfgIDToken                  = "id-token"
	cfgRefreshToken             = "refresh-token"
)

var (
	backoff = wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Jitter:   .1,
		Steps:    5,
	}
)

func init() {
	if err := restclient.RegisterAuthProviderPlugin("oidc", newAuthProvider); err != nil {
		glog.Fatalf("Failed to register oidc auth plugin: %v", err)
	}
}

func newAuthProvider(_ string, cfg map[string]string, persister restclient.AuthProviderConfigPersister) (restclient.AuthProvider, error) {
	issuer := cfg[cfgIssuerUrl]
	if issuer == "" {
		return nil, fmt.Errorf("Must provide %s", cfgIssuerUrl)
	}

	clientID := cfg[cfgClientID]
	if clientID == "" {
		return nil, fmt.Errorf("Must provide %s", cfgClientID)
	}

	clientSecret := cfg[cfgClientSecret]
	if clientSecret == "" {
		return nil, fmt.Errorf("Must provide %s", cfgClientSecret)
	}

	tlsConfig := restclient.TLSClientConfig{CAFile: cfg[cfgCertificateAuthority]}

	if cfg[cfgCertificateAuthorityData] != "" {
		caData, err := base64.StdEncoding.DecodeString(cfg[cfgCertificateAuthorityData])
		if err != nil {
			return nil, fmt.Errorf("failed to decode ca data: %v", err)
		}
		tlsConfig.CAData = caData
	}

	clientConfig := restclient.Config{TLSClientConfig: tlsConfig}

	trans, err := restclient.TransportFor(&clientConfig)
	if err != nil {
		return nil, err
	}

	return &authProvider{
		issuerURL:    issuer,
		issuerClient: &http.Client{Transport: trans},

		clientID:     clientID,
		clientSecret: clientSecret,

		refreshToken: cfg[cfgRefreshToken],
		idToken:      cfg[cfgIDToken],
		persister:    persister,
		cfg:          cfg,

		now: func() time.Time {
			return time.Now().Add(expiryDelta)
		},
	}, nil
}

type authProvider struct {
	issuerURL    string
	issuerClient *http.Client

	clientID     string
	clientSecret string

	refreshToken string

	now func() time.Time

	provider atomic.Value // always of type *oidc.Provider

	// mu guards all of the following fields
	mu      sync.Mutex
	idToken string
	// TODO(ericchiang): AuthProviderConfigPersister is racy because we can
	// only write to it and never read. Need to figure out how to deal with
	// concurrent clients using the same provider.
	persister restclient.AuthProviderConfigPersister
	cfg       map[string]string
}

func (p *authProvider) getProvider() (*oidc.Provider, bool) {
	provider, ok := p.provider.Load().(*oidc.Provider)
	return provider, ok
}

func (p *authProvider) setProvider(provider *oidc.Provider) {
	p.provider.Store(provider)
}

func (p *authProvider) setIDToken(idToken string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	newCfg := make(map[string]string, len(p.cfg))
	for key, val := range p.cfg {
		newCfg[key] = val
	}
	newCfg[cfgIDToken] = idToken

	if err := p.persister.Persist(newCfg); err != nil {
		return err
	}
	p.cfg = newCfg
	p.idToken = idToken

	return nil
}

func (p *authProvider) getIDToken() (idToken string, valid bool) {
	p.mu.Lock()
	idToken = p.idToken
	p.mu.Unlock()

	if idToken == "" {
		return "", false
	}

	// Parse the JWT payload. Because the API server does its own verification of the
	// id token, don't bother trying to verify it here.
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}

	// Unmarshal payload.
	var t struct {
		// Some providers return floats. blah.
		Expiry json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &t); err != nil {
		return "", false
	}

	var expiry time.Time
	if n, err := t.Expiry.Int64(); err != nil {
		if f, err := t.Expiry.Float64(); err != nil {
			return "", false
		} else {
			expiry = time.Unix(int64(f), 0)
		}
	} else {
		expiry = time.Unix(n, 0)
	}

	return idToken, p.now().After(expiry)
}

func (a *authProvider) WrapTransport(rt http.RoundTripper) http.RoundTripper {
	return &transport{a, rt}
}

// TODO(ericchiang): Login is never called and doesn't have a concrete implementation between
// any of the existing AuthProviders. Should probably remove it from the AuthProvider interface
// until we have evidence that it's useful.
func (g *authProvider) Login() error {
	return errors.New("not yet implemented")
}

type transport struct {
	provider  *authProvider
	transport http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	idToken, ok := t.provider.getIDToken()
	if !ok {
		ctx := context.WithValue(context.TODO(), oauth2.HTTPClient, t.provider.issuerClient)

		p, ok := t.provider.getProvider()
		if !ok {
			provider, err := oidc.NewProvider(ctx, t.provider.issuerURL)
			if err != nil {
				return nil, err
			}
			t.provider.setProvider(provider)
			p = provider
		}

		config := oauth2.Config{
			ClientID:     t.provider.clientID,
			ClientSecret: t.provider.clientSecret,
			Endpoint:     p.Endpoint(),
		}

		ts := config.TokenSource(ctx, &oauth2.Token{RefreshToken: t.provider.refreshToken})

		token, err := ts.Token()
		if err != nil {
			return nil, fmt.Errorf("refreshing token: %v", err)
		}
		idToken, ok = token.Extra("id_token").(string)
		if !ok {
			return nil, fmt.Errorf("oidc: refreshed token did not contain an id_token field")
		}

		if err := t.provider.setIDToken(idToken); err != nil {
			return nil, fmt.Errorf("oidc: failed to persist new id token: %v", err)
		}
	}
	req.Header.Set("Authorization", "Bearer "+idToken)
	return t.transport.RoundTrip(req)
}
