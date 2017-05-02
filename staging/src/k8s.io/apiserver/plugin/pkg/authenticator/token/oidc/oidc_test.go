/*
Copyright 2015 The Kubernetes Authors.

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
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	jose "gopkg.in/square/go-jose.v2"

	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidctest"
)

func TestClaimsParsing(t *testing.T) {
	rawClaims := []byte(`{
     "iss": "https://server.example.com",
     "sub": "24400320",
     "aud": "s6BhdRkqt3",
     "nonce": "n-0S6_WzA2Mj",
     "exp": 1311281970,
     "iat": 1311280970,
     "auth_time": 1311280969,
     "acr": "urn:mace:incommon:iap:silver"
    }`)

	c := new(claims)
	if err := json.Unmarshal(rawClaims, c); err != nil {
		t.Fatal(err)
	}

	var (
		issuer     string
		wantIssuer string = "https://server.example.com"
	)
	found, err := c.claim("iss", &issuer)
	switch {
	case err != nil:
		t.Errorf("failed to parse issuer claim: %v", err)
	case !found:
		t.Errorf("iss claim not found")
	case issuer != wantIssuer:
		t.Errorf("expected issuer %s got %s", wantIssuer, issuer)
	}

	var (
		exp     int
		wantExp int = 1311281970
	)
	found, err = c.claim("exp", &exp)
	switch {
	case err != nil:
		t.Errorf("failed to parse exp claim: %v", err)
	case !found:
		t.Errorf("exp claim not found")
	case exp != wantExp:
		t.Errorf("expected exp %d got %d", wantExp, exp)
	}

	found, err = c.claim("no a key", &exp)
	switch {
	case err != nil:
		t.Errorf("expected nil error for unfound key, got: %v", err)
	case found:
		t.Errorf("expected key not found")
	}
}

func TestOIDCPlugin(t *testing.T) {
	var p *oidctest.Provider
	f := func(w http.ResponseWriter, r *http.Request) { p.ServeHTTP(w, r) }
	s := httptest.NewUnstartedServer(http.HandlerFunc(f))
	cert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatal(err)
	}
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	defer s.Close()

	p, err = oidctest.NewProvider(s.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()

	tests := []struct {
		name    string
		options OIDCOptions
		// Claims are marshaled and signed by the provider.
		claims map[string]interface{}

		wantErr bool

		wantName   string
		wantGroups []string
	}{
		{
			name: "valid_token",
			options: OIDCOptions{
				IssuerURL:     s.URL,
				ClientID:      "myid",
				CAFile:        "testdata/ca.crt",
				UsernameClaim: "sub",
			},
			claims: map[string]interface{}{
				"iss": s.URL,
				"aud": "myid",
				"sub": "1234",
				"exp": now.Add(time.Hour).Unix(),
				"iat": now.Unix(),
			},
			wantName: s.URL + "#" + "1234",
		},
		{
			name: "wrong_issuer",
			options: OIDCOptions{
				IssuerURL:     s.URL,
				ClientID:      "myid",
				CAFile:        "testdata/ca.crt",
				UsernameClaim: "sub",
			},
			claims: map[string]interface{}{
				"iss": "https://example.com",
				"aud": "myid",
				"sub": "1234",
				"exp": now.Add(time.Hour).Unix(),
				"iat": now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "wrong_ca",
			options: OIDCOptions{
				IssuerURL:     s.URL,
				ClientID:      "myid",
				CAFile:        "testdata/bad.crt",
				UsernameClaim: "sub",
			},
			claims: map[string]interface{}{
				"iss": s.URL,
				"aud": "myid",
				"sub": "1234",
				"exp": now.Add(time.Hour).Unix(),
				"iat": now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "email",
			options: OIDCOptions{
				IssuerURL:     s.URL,
				ClientID:      "myid",
				CAFile:        "testdata/ca.crt",
				UsernameClaim: "email",
			},
			claims: map[string]interface{}{
				"iss":            s.URL,
				"aud":            "myid",
				"email":          "jane.doe@example.com",
				"email_verified": true,
				"sub":            "1234",
				"exp":            now.Add(time.Hour).Unix(),
				"iat":            now.Unix(),
			},
			wantName: "jane.doe@example.com",
		},
		{
			name: "email_not_verified",
			options: OIDCOptions{
				IssuerURL:     s.URL,
				ClientID:      "myid",
				CAFile:        "testdata/ca.crt",
				UsernameClaim: "email",
			},
			claims: map[string]interface{}{
				"iss":            s.URL,
				"aud":            "myid",
				"email":          "jane.doe@example.com",
				"email_verified": false,
				"sub":            "1234",
				"exp":            now.Add(time.Hour).Unix(),
				"iat":            now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "email_verified_not_present",
			options: OIDCOptions{
				IssuerURL:     s.URL,
				ClientID:      "myid",
				CAFile:        "testdata/ca.crt",
				UsernameClaim: "email",
			},
			claims: map[string]interface{}{
				"iss":   s.URL,
				"aud":   "myid",
				"email": "jane.doe@example.com",
				"sub":   "1234",
				"exp":   now.Add(time.Hour).Unix(),
				"iat":   now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "wrong_client_id",
			options: OIDCOptions{
				IssuerURL:     s.URL,
				ClientID:      "myid",
				CAFile:        "testdata/ca.crt",
				UsernameClaim: "email",
			},
			claims: map[string]interface{}{
				"iss":   s.URL,
				"aud":   "badid",
				"email": "jane.doe@example.com",
				"sub":   "1234",
				"exp":   now.Add(time.Hour).Unix(),
				"iat":   now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "multiple_audiences",
			options: OIDCOptions{
				IssuerURL:     s.URL,
				ClientID:      "myid",
				CAFile:        "testdata/ca.crt",
				UsernameClaim: "email",
			},
			claims: map[string]interface{}{
				"iss":   s.URL,
				"aud":   []string{"badid", "myid"},
				"email": "jane.doe@example.com",
				"sub":   "1234",
				"exp":   now.Add(time.Hour).Unix(),
				"iat":   now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "expired_token",
			options: OIDCOptions{
				IssuerURL:     s.URL,
				ClientID:      "myid",
				CAFile:        "testdata/ca.crt",
				UsernameClaim: "email",
			},
			claims: map[string]interface{}{
				"iss":            s.URL,
				"aud":            "myid",
				"email":          "jane.doe@example.com",
				"email_verified": true,
				"sub":            "1234",
				"exp":            now.Add(-time.Hour).Unix(),
				"iat":            now.Add(-2 * time.Hour).Unix(),
			},
			wantErr: true,
		},
		{
			name: "groups",
			options: OIDCOptions{
				IssuerURL:     s.URL,
				ClientID:      "myid",
				CAFile:        "testdata/ca.crt",
				UsernameClaim: "sub",
				GroupsClaim:   "groups",
			},
			claims: map[string]interface{}{
				"iss":    s.URL,
				"aud":    "myid",
				"sub":    "1234",
				"exp":    now.Add(time.Hour).Unix(),
				"iat":    now.Unix(),
				"groups": []string{"team1", "team2"},
			},
			wantName:   s.URL + "#" + "1234",
			wantGroups: []string{"team1", "team2"},
		},
		{
			name: "single_group",
			options: OIDCOptions{
				IssuerURL:     s.URL,
				ClientID:      "myid",
				CAFile:        "testdata/ca.crt",
				UsernameClaim: "sub",
				GroupsClaim:   "groups",
			},
			claims: map[string]interface{}{
				"iss":    s.URL,
				"aud":    "myid",
				"sub":    "1234",
				"exp":    now.Add(time.Hour).Unix(),
				"iat":    now.Unix(),
				"groups": "team1",
			},
			wantName:   s.URL + "#" + "1234",
			wantGroups: []string{"team1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a, err := New(test.options)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()

			data, err := json.Marshal(test.claims)
			if err != nil {
				t.Fatal(err)
			}
			jwt, err := p.Sign(data)
			if err != nil {
				t.Fatal(err)
			}

			user, ok, err := a.AuthenticateToken(jwt)
			if err != nil {
				if !test.wantErr {
					t.Errorf("authenticating token: %v", err)
				}
				return
			}

			if !ok {
				t.Errorf("no user found in JWT")
				return
			}

			if gotName := user.GetName(); gotName != test.wantName {
				t.Errorf("wanted username %q got %q", test.wantName, gotName)
			}

			gotGroups := user.GetGroups()
			if !slicesMatch(gotGroups, test.wantGroups) {
				t.Errorf("wanted groups %q got %q", test.wantGroups, gotGroups)
			}
		})
	}
}

func slicesMatch(s1, s2 []string) bool {
	sort.Strings(s1)
	sort.Strings(s2)
	if len(s1) != len(s2) {
		return false
	}
	for i, s := range s1 {
		if s2[i] != s {
			return false
		}
	}
	return true
}

func TestInvalidJWTSignature(t *testing.T) {
	var p *oidctest.Provider
	f := func(w http.ResponseWriter, r *http.Request) { p.ServeHTTP(w, r) }
	s := httptest.NewUnstartedServer(http.HandlerFunc(f))
	cert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatal(err)
	}
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	defer s.Close()

	p, err = oidctest.NewProvider(s.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	opts := OIDCOptions{
		IssuerURL:     s.URL,
		ClientID:      "myid",
		CAFile:        "testdata/ca.crt",
		UsernameClaim: "sub",
	}

	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	p2, err := oidctest.NewProvider(s.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := map[string]interface{}{
		"iss": s.URL,
		"aud": "myid",
		"sub": "1234",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	goodJWT, err := p.Sign(data)
	if err != nil {
		t.Fatal(err)
	}
	badJWT, err := p2.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := a.AuthenticateToken(goodJWT); err != nil {
		t.Errorf("failed to authenticate good token: %v", err)
	}
	if _, _, err := a.AuthenticateToken(badJWT); err == nil {
		t.Errorf("incorrectly authenticated token")
	}
}

func TestInvalidSigningAlg(t *testing.T) {
	testOpts := oidctest.Options{
		NewKey: func() (priv, pub interface{}, err error) {
			return []byte("foo"), []byte("foo"), nil
		},
		// Invalid signature algorithm. Ensure the plugin rejects this.
		//
		// We actually had a bug report once where the server was using this
		// signature algorithm.
		SigAlg: jose.HS256,
	}

	var p *oidctest.Provider
	f := func(w http.ResponseWriter, r *http.Request) { p.ServeHTTP(w, r) }
	s := httptest.NewUnstartedServer(http.HandlerFunc(f))
	cert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatal(err)
	}
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	defer s.Close()

	p, err = oidctest.NewProvider(s.URL, &testOpts)
	if err != nil {
		t.Fatal(err)
	}

	opts := OIDCOptions{
		IssuerURL:     s.URL,
		ClientID:      "myid",
		CAFile:        "testdata/ca.crt",
		UsernameClaim: "sub",
	}

	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	now := time.Now()
	claims := map[string]interface{}{
		"iss": s.URL,
		"aud": "myid",
		"sub": "1234",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := p.Sign(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.AuthenticateToken(jwt); err == nil {
		t.Errorf("authenticator verified an invalid signature algorithm")
	}
}

// TestUnavailableProvider ensure the authenticator can authenticate even if
// it's initialized when the provider is unavailable.
func TestUnavailableProvider(t *testing.T) {
	var (
		p         *oidctest.Provider
		available int32 // 0 if unavailable.
	)
	f := func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&available) == 0 {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		p.ServeHTTP(w, r)
	}

	s := httptest.NewUnstartedServer(http.HandlerFunc(f))
	cert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatal(err)
	}
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	defer s.Close()

	p, err = oidctest.NewProvider(s.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := map[string]interface{}{
		"iss": s.URL,
		"aud": "myid",
		"sub": "1234",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	jwt, err := p.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	opts := OIDCOptions{
		IssuerURL:     s.URL,
		ClientID:      "myid",
		CAFile:        "testdata/ca.crt",
		UsernameClaim: "sub",
	}

	pollInterval := time.Millisecond * 50
	a, err := newWithPollInterval(opts, pollInterval)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	if _, _, err := a.AuthenticateToken(jwt); err == nil {
		t.Errorf("incorrectly authenticated token when provider was unavailabe")
	}

	// Make provider available
	atomic.StoreInt32(&available, 1)

	var lastErr error
	for i := 0; i < 20; i++ {
		time.Sleep(pollInterval)
		_, _, lastErr = a.AuthenticateToken(jwt)
		if lastErr == nil {
			return
		}
	}
	t.Errorf("failed to authenticate token: %v", lastErr)
}
