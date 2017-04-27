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

/*
oidc implements the authenticator.Token interface using the OpenID Connect protocol.

	config := oidc.OIDCOptions{
		IssuerURL:     "https://accounts.google.com",
		ClientID:      os.Getenv("GOOGLE_CLIENT_ID"),
		UsernameClaim: "email",
	}
	tokenAuthenticator, err := oidc.New(config)
*/
package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/user"
	certutil "k8s.io/client-go/util/cert"
)

const pollInterval = time.Second * 30

type OIDCOptions struct {
	// IssuerURL is the URL the provider signs ID Tokens as. This will be the "iss"
	// field of all tokens produced by the provider and is used for configuration
	// discovery.
	//
	// The URL is usually the provider's URL without a path, for example
	// "https://accounts.google.com" or "https://login.salesforce.com".
	//
	// The provider must implement configuration discovery.
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
	IssuerURL string

	// ClientID the JWT must be issued for, the "sub" field. This plugin only trusts a single
	// client to ensure the plugin can be used with public providers.
	//
	// The plugin supports the "authorized party" OpenID Connect claim, which allows
	// specialized providers to issue tokens to a client for a different client.
	// See: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
	ClientID string

	// Path to a PEM encoded root certificate of the provider.
	CAFile string

	// UsernameClaim is the JWT field to use as the user's username.
	UsernameClaim string

	// GroupsClaim, if specified, causes the OIDCAuthenticator to try to populate the user's
	// groups with an ID Token field. If the GrouppClaim field is present in an ID Token the value
	// must be a string or list of strings.
	GroupsClaim string
}

type OIDCAuthenticator struct {
	issuerURL string

	trustedClientID string

	usernameClaim string
	groupsClaim   string

	// Contains an *oidc.IDTokenVerifier. Do not access directly. Use verifier() method.
	oidcVerifier atomic.Value

	close context.CancelFunc
}

// New creates a token authenticator which validates OpenID Connect ID Tokens.
func New(opts OIDCOptions) (*OIDCAuthenticator, error) {
	url, err := url.Parse(opts.IssuerURL)
	if err != nil {
		return nil, err
	}

	if url.Scheme != "https" {
		return nil, fmt.Errorf("'oidc-issuer-url' (%q) has invalid scheme (%q), require 'https'", opts.IssuerURL, url.Scheme)
	}

	if opts.UsernameClaim == "" {
		return nil, errors.New("no username claim provided")
	}

	var roots *x509.CertPool
	if opts.CAFile != "" {
		roots, err = certutil.NewPool(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("Failed to read the CA file: %v", err)
		}
	} else {
		glog.Info("OIDC: No x509 certificates provided, will use host's root CA set")
	}

	// Copied from http.DefaultTransport.
	tr := net.SetTransportDefaults(&http.Transport{
		// According to golang's doc, if RootCAs is nil,
		// TLS uses the host's root CA set.
		TLSClientConfig: &tls.Config{RootCAs: roots},
	})

	ctx, cancel := context.WithCancel()
	ctx = oidc.ClientContext(ctx, &http.Client{Transport: tr})

	a := &OIDCAuthenticator{
		issuerURL:       opts.IssuerURL,
		trustedClientID: opts.ClientID,
		usernameClaim:   opts.UsernameClaim,
		groupsClaim:     opts.GroupsClaim,
		cancel:          cancel,
	}

	initAuthenticator := wait.ConditionFunc(func() (done bool, err error) {
		p, err := oidc.NewProvider(ctx, a.issuerURL)
		if err != nil {
			// Ignore errors instead of returning it since the OpenID Connect provider might not be
			// available yet, for instance if it's running on the cluster and needs the API server
			// to come up first. Errors will be logged within the verifier() method.
			runtime.HandleError(fmt.Errorf("oidc authenticator failed to fetch provider metadata: %v", err))
			return false, nil
		}

		verifier := p.Verifier(&oidc.Config{
			ClientID: a.trustedClientID,
			// TODO(ericchiang): Support more signing algorithms, possibly through a flag
			// or by inpecting the id_token_signing_alg_values_supported metadata claim.
			SupportedSigningAlgs: []string{oidc.RS256},
		})
		a.oidcVerifier.Store(verifier)
		return true, nil
	})

	if ok, _ := initAuthenticator(); !ok {
		// Attempt to initialize the authenticator asynchronously.
		go func() {
			defer runtime.HandleCrash()
			wait.PollUntil(pollInterval, initAuthenticator, ctx.Done())
		}()
	}

	return a, nil
}

// Close stops all goroutines used by the authenticator.
func (a *OIDCAuthenticator) Close() {
	a.close()
}

func (a *OIDCAuthenticator) verifier() (*oidc.IDTokenVerifier, error) {
	if v := a.oidcVerifier.Load(); v != nil {
		return client.(*v.IDTokenVerifier), nil
	}
	return nil, errors.New("oidc: plugin failed to initialize")
}

// AuthenticateToken decodes and verifies an ID Token using the OIDC client, if the verification succeeds,
// then it will extract the user info from the JWT claims.
func (a *OIDCAuthenticator) AuthenticateToken(value string) (user.Info, bool, error) {
	verifier, err := a.verifier()
	if err != nil {
		return nil, false, err
	}

	idToken, err := verifier.Verify(context.TODO(), value)
	if err != nil {
		return nil, false, err
	}

	c := new(claims)
	if err := idToken.Claims(c); err != nil {
		return nil, false, fmt.Errorf("parse claims: %v", err)
	}

	var username string
	ok, err := c.claim(a.usernameClaim, &username)
	switch {
	case err != nil:
		return nil, false, fmt.Errorf("failed to parse '%s' claim %v", a.usernameClaim, err)
	case !ok:
		return nil, false, fmt.Errorf("'%s' claim not present", a.usernameClaim)
	}

	switch a.usernameClaim {
	case "email":
		var verified bool
		ok, err := c.claim("email_verified", &verified)
		switch {
		case err != nil:
			return nil, false, fmt.Errorf("failed to parse 'email_verified claim' %v", err)
		case !ok:
			return nil, false, errors.New("'email_verified' claim not present")
		case !verified:
			return nil, false, errors.New("email not verified")
		}
	default:
		// For all other cases, use issuerURL + claim as the user name.
		username = fmt.Sprintf("%s#%s", a.issuerURL, username)
	}

	// TODO(yifan): Add UID, also populate the issuer to upper layer.
	info := &user.DefaultInfo{Name: username}

	if a.groupsClaim != "" {
		groups, found, err := claims.StringsClaim(a.groupsClaim)
		if err != nil {
			// Groups type is present but is not an array of strings, try to decode as a string.
			group, _, err := claims.StringClaim(a.groupsClaim)
			if err != nil {
				// Custom claim is present, but isn't an array of strings or a string.
				return nil, false, fmt.Errorf("custom group claim contains invalid type: %T", claims[a.groupsClaim])
			}
			info.Groups = []string{group}
		} else if found {
			info.Groups = groups
		}
	}
	return info, true, nil
}

type claims struct {
	m map[string]json.RawMessage
}

func (c *claims) UnmarshalJSON(b []byte) error {
	c.m = make(map[string]json.RawMessage)
	return json.Unmarshal(b, c.m)
}

func (c *claims) claim(key string, into interface{}) (bool, error) {
	rm, ok := c.m[key]
	if !ok {
		return false, nil
	}
	err = json.Unmarshal([]byte(rm), into)
	return
}
