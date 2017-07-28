/*
Copyright 2017 The Kubernetes Authors.

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

package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	"k8s.io/client-go/rest"
)

var (
	caCertData = newCertificateData(`-----BEGIN CERTIFICATE-----
MIICBjCCAW+gAwIBAgIJAN1BCjocWGFOMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAMMEHdlYmhvb2tfdGVzdHNfY2EwIBcNMTcwNzI4MjMxNTI4WhgPMjI5MTA1MTMy
MzE1MjhaMBsxGTAXBgNVBAMMEHdlYmhvb2tfdGVzdHNfY2EwgZ8wDQYJKoZIhvcN
AQEBBQADgY0AMIGJAoGBALuhuOhj+dvZWYg3z+oq2h8bOEI1uqwp9Dm+HRZRY3Am
lQYYHKdjII5B5foQSK4JAEcCU1EU+OGbCDqpoXrz4F+/ZMPD6kG5i3Lb1FMuG7KO
qBSPhnX6jwk8ivyyye9pEOvz48kM+T9BvRDbSnLs2EpL2A2Fu1DIX7iHl9WdoMoF
AgMBAAGjUDBOMB0GA1UdDgQWBBT3xCywmRQm0uEKmhlld8XLVfGI3zAfBgNVHSME
GDAWgBT3xCywmRQm0uEKmhlld8XLVfGI3zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4GBAAvtbdmNoLFYW+7Z1/0P17stTY2gtIzpcWjbx/Nq5bT3HjYgL1t1
bi/5RlczW2D4ZVVXDL1/+/OrW1TaYYM/wk043ja5ykbOMEQqmHpHUTVDEYm7Wj0R
8qX2Gel0vsAFbFDs9KloyCuNFS4gETycaBB8Y0t1msQxmXkXXKzk2nH9
-----END CERTIFICATE-----`, `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC7objoY/nb2VmIN8/qKtofGzhCNbqsKfQ5vh0WUWNwJpUGGByn
YyCOQeX6EEiuCQBHAlNRFPjhmwg6qaF68+Bfv2TDw+pBuYty29RTLhuyjqgUj4Z1
+o8JPIr8ssnvaRDr8+PJDPk/Qb0Q20py7NhKS9gNhbtQyF+4h5fVnaDKBQIDAQAB
AoGBAIPDaz3PT5yjQuuU/i5cz3Z+wABHCQN0Ju0R5A1TNHiCr65q6lxmEWu1PVJh
cxi8e3RiXq4XAzwzihDgJOVaNBr1VB929nQphZy5QJRLmaH/rvYd80xDr/sYuVz7
ldAsj7GZmI8Q2F0g2wLD/0peQTy7rkudvn9R2dhX2IQfFAmhAkEA2zfKG+xUhKZE
yAw6V91vD5yJLUmbUOesAjIxU/7+DfO/HtCNWxaibD+xOwB0mBBD+upfFMpvt44x
tv9ZW1rw/QJBANsdMK9XIAfeWn/oe+n8FYKFl0scw2Ump/pCbIaFUx6EfEBNI9ix
Iol5A8Mv/K/t+5kHUSitvup8ntoRuuCib6kCQBAprN0iL5kYKToWrLaNvQKJqBOO
ucTdT/FZggmPY2vj7NN4zPNKV+9jQs322qHbkSeO4DPIOTRvZ3r2mMADlIECQQC8
7UJZLUpU/ogR2adebRku3XlCLp7bzKTxx+xDYRn2Kk3oM5tA8BrTZiC0X+AE4bIa
lJCJ/qWrEaD2bmsv3V9hAkArNqjDQ1CBetq2pe6xznJRfRLHaSzCHauspeuz1OkO
nFOqcAwiuyxa1SrtpZoreZZE+rgCDGr6tGhPzzw4/Eud
-----END RSA PRIVATE KEY-----`)
	client1CertData = newCertificateData(`-----BEGIN CERTIFICATE-----
MIICBDCCAW2gAwIBAgIJAPgVBh+4xbGoMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAMMEHdlYmhvb2tfdGVzdHNfY2EwIBcNMTcwNzI4MjMxNTI4WhgPMjI5MTA1MTMy
MzE1MjhaMB8xHTAbBgNVBAMMFHdlYmhvb2tfdGVzdHNfY2xpZW50MIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQDkGXXSm6Yun5o3Jlmx45rItcQ2pmnoDk4eZfl0
rmPa674s2pfYo3KywkXQ1Fp3BC8GUgzPLSfJ8xXya9Lg1Wo8sHrDln0iRg5HXxGu
uFNhRBvj2S0sIff0ZG/IatB9I6WXVOUYuQj6+A0CdULNj1vBqH9+7uWbLZ6lrD4b
a44x/wIDAQABo0owSDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAdBgNVHSUEFjAU
BggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0RBAgwBocEfwAAATANBgkqhkiG9w0B
AQsFAAOBgQCpN27uh/LjUVCaBK7Noko25iih/JSSoWzlvc8CaipvSPofNWyGx3Vu
OdcSwNGYX/pp4ZoAzFij/Y5u0vKTVLkWXATeTMVmlPvhmpYjj9gPkCSY6j/SiKlY
kGy0xr+0M5UQkMBcfIh9oAp9um1fZHVWAJAGP/ikZgkcUey0LmBn8w==
-----END CERTIFICATE-----`, `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDkGXXSm6Yun5o3Jlmx45rItcQ2pmnoDk4eZfl0rmPa674s2pfY
o3KywkXQ1Fp3BC8GUgzPLSfJ8xXya9Lg1Wo8sHrDln0iRg5HXxGuuFNhRBvj2S0s
Iff0ZG/IatB9I6WXVOUYuQj6+A0CdULNj1vBqH9+7uWbLZ6lrD4ba44x/wIDAQAB
AoGAZbWwowvCq1GBq4vPPRI3h739Uz0bRl1ymf1woYXNguXRtCB4yyH+2BTmmrrF
6AIWkePuUEdbUaKyK5nGu3iOWM+/i6NP3kopQANtbAYJ2ray3kwvFlhqyn1bxX4n
gl/Cbdw1If4zrDrB66y8mYDsjzK7n/gFaDNcY4GArjvOXKkCQQD9Lgv+WD73y4RP
yS+cRarlEeLLWVsX/pg2oEBLM50jsdUnrLSW071MjBgP37oOXzqynF9SoDbP2Y5C
x+aGux9LAkEA5qPlQPv0cv8Wc3qTI+LixZ/86PPHKWnOnwaHm3b9vQjZAkuVQg3n
Wgg9YDmPM87t3UFH7ZbDihUreUxwr9ZjnQJAZ9Z95shMsxbOYmbSVxafu6m1Sc+R
M+sghK7/D5jQpzYlhUspGf8n0YBX0hLhXUmjamQGGH5LXL4Owcb4/mM6twJAEVio
SF/qva9jv+GrKVrKFXT374lOJFY53Qn/rvifEtWUhLCslCA5kzLlctRBafMZPrfH
Mh5RrJP1BhVysDbenQJASGcc+DiF7rB6K++ZGyC11E2AP29DcZ0pgPESSV7npOGg
+NqPRZNVCSZOiVmNuejZqmwKhZNGZnBFx1Y+ChAAgw==
-----END RSA PRIVATE KEY-----`)
	client2CertData = newCertificateData(`-----BEGIN CERTIFICATE-----
MIICBDCCAW2gAwIBAgIJAPgVBh+4xbGnMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAMMEHdlYmhvb2tfdGVzdHNfY2EwIBcNMTcwNzI4MjMxNTI4WhgPMjI5MTA1MTMy
MzE1MjhaMB8xHTAbBgNVBAMMFHdlYmhvb2tfdGVzdHNfY2xpZW50MIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQDQQLzbrmHbtlxE7wViaoXFp5tQx7zzM2Ed7O1E
gs3JUws5KkPbNrejLwixvLkzzU152M43UGsyKDn7HPyjXDogTZSW6C257XpYodk3
S/gZS9oZtPss4UJuJioQk/M8X1ZjYP8kCTArOvVRJeNQL8GM7h5QQ6J5LUq+IdZb
T0retQIDAQABo0owSDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAdBgNVHSUEFjAU
BggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0RBAgwBocEfwAAATANBgkqhkiG9w0B
AQsFAAOBgQBdAxoU5YAmp0d+5b4qg/xOGC5rKcnksQEXYoGwFBWwaKvh9oUlGGxI
A5Ykf2TEl24br4tLmicpdxUX4H4PbkdPxOjM9ghIKlmgHo8vBRC0iVIwYgQsw1W8
ETY34Or+PJqaeslqx/t7kUKY5UIF9DLVolsIiAHveJNR2uBWiP0KiQ==
-----END CERTIFICATE-----`, `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDQQLzbrmHbtlxE7wViaoXFp5tQx7zzM2Ed7O1Egs3JUws5KkPb
NrejLwixvLkzzU152M43UGsyKDn7HPyjXDogTZSW6C257XpYodk3S/gZS9oZtPss
4UJuJioQk/M8X1ZjYP8kCTArOvVRJeNQL8GM7h5QQ6J5LUq+IdZbT0retQIDAQAB
AoGBAMFjTL4IKvG4X+jXub1RxFXvNkkGos2Jaec7TH5xpZ4OUv7L4+We41tTYxSC
d83GGetLzPwK3vDd8DHkEiu1incket78rwmQ89LnQNyM0B5ejaTjW2zHcvKJ0Mtn
nM32juQfq8St9JZVweS87k8RkLt9cOrg6219MRbFO+1Vn8WhAkEA+/rqHCspBdXr
7RL+H63k7RjqBllVEYlw1ukqTw1gp5IImmeOwgl3aRrJJfFV6gxxEqQ4CCb2vf9M
yjrGEvP9KQJBANOTPcpskT/0dyipsAkvLFZTKjN+4fdfq37H3dVgMR6oQcMJwukd
cEio1Hx+XzXuD0RHXighq7bUzel+IqzRuq0CQBJkzpIf1G7InuA/cq19VCi6mNq9
yqftEH+fpab/ov6YemhLBvDDICRcADL02wCqx9ZEhpKRxZE5AbIBeFQJ24ECQG4f
9cmnOPNRC7TengIpy6ojH5QuNu/LnDghUBYAO5D5g0FBk3JDIG6xceha3rPzdX7U
pu28mORRX9xpCyNpBwECQQCtDNZoehdPVuZA3Wocno31Rjmuy83ajgRRuEzqv0tj
uC6Jo2eLcSV1sSdzTjaaWdM6XeYj6yHOAm8ZBIQs7m6V
-----END RSA PRIVATE KEY-----`)
	serverCertData = newCertificateData(`-----BEGIN CERTIFICATE-----
MIICiDCCAfGgAwIBAgIJAPgVBh+4xbGmMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAMMEHdlYmhvb2tfdGVzdHNfY2EwIBcNMTcwNzI4MjMxNTI4WhgPMjI5MTA1MTMy
MzE1MjhaMB8xHTAbBgNVBAMMFHdlYmhvb2tfdGVzdHNfc2VydmVyMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxlXzXqDlS4PdAo61Ij2RCNKt5yYaDUGD
b80KjOypQOl6ZbM55HECDxfugMRuMY6R6EAil2j2DpGYh6ujUeMbsMizyJV+WASo
2VDcQge9GSTJdNwogvMmNFcXt8P9kITACKuA1IN3hnE1CLpUNjBJ6rAplctfwvS4
ui32P+vnuIgFKnJ76Ko0uLfAcPVxLPZDDZMrihrK/D1OZtYcW9KoblFd8M7SWpPy
h53QP9W7Kxt6+WjHR9YqBkFt1CMkyZsFALGVNjJ/zNX1Yl2ufALgr682LgAIk+0O
npjbJiS1Hecn2LMiqcuOuhP4F6zb3g9s0xqQIIlw0lq1kOUMlAMfEwIDAQABo0ow
SDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAdBgNVHSUEFjAUBggrBgEFBQcDAgYI
KwYBBQUHAwEwDwYDVR0RBAgwBocEfwAAATANBgkqhkiG9w0BAQsFAAOBgQCV/Php
pnFWMfQNwyyRkYgLnFk3m8fOzp//zvpKcz9c28Zkhdr3rrOTiqBiR2ED1bQ5kwjJ
N6+c8jtKXJG0BWKhR/m0kI2b93DluDYcy2xA8QZxJHWZF2M364tegEoacEqJZX7E
XgKBtwBt+ngbT3crVJEYMsit6fUSDSFyn3yR2w==
-----END CERTIFICATE-----`, `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxlXzXqDlS4PdAo61Ij2RCNKt5yYaDUGDb80KjOypQOl6ZbM5
5HECDxfugMRuMY6R6EAil2j2DpGYh6ujUeMbsMizyJV+WASo2VDcQge9GSTJdNwo
gvMmNFcXt8P9kITACKuA1IN3hnE1CLpUNjBJ6rAplctfwvS4ui32P+vnuIgFKnJ7
6Ko0uLfAcPVxLPZDDZMrihrK/D1OZtYcW9KoblFd8M7SWpPyh53QP9W7Kxt6+WjH
R9YqBkFt1CMkyZsFALGVNjJ/zNX1Yl2ufALgr682LgAIk+0OnpjbJiS1Hecn2LMi
qcuOuhP4F6zb3g9s0xqQIIlw0lq1kOUMlAMfEwIDAQABAoIBAEXhdM1LnV6dCFrl
UzbMQHS+Xl2KFDXFdn0G3ofGvt/LI7//hQ9TLemJghRGoZi+ZfRR3J5Cciex7u8m
b3Xjshb4sDelTI3QnnlrPx/YwCzCxGRzSabR6w0X/phV6tpnm42yd8Loy01IR+pa
VF9/ZhvVk+FeddAoD4oxtYjSIqPmUUzC096RHdn4ywzzAjCdi392+PQmoVFyz7Vy
GcJha9UpuaDwPBVOGZHQ4x09XvZ6o99dFT2V09hlGy+q4hTL4yq4ct9tfoDiy0w1
lU4Ov689nNcZ5GRQ3sZZwrRyFC+0cArCkX5EROqZ+vYfpNfdrTAQs30nqBeA5vwK
fH8Y78ECgYEA+wtEsmCeOHcQ1ziGSn/KtkJHJTNX/DzdvwgS51CU9lnii/9onRCa
eXZ3V+bW4Lxk17UjD06YAhuvfJBmjvgRGfm6MlKyUJ/eCXLJJXcgb4tkLd/94s4W
3y84K0jxoIDsW3v3QdBU3XG7n8zSh27uqhaRh9RQDH3nzoCDfAjC7DMCgYEAykBN
2ouBiBn6Iz1EbAFDwwS4XoJQSgpZrrKty/idEi7NOXvzG23ZPuK283lDXbL6VBYb
vPoyC2vcuds+tgolqaHC5ViBGvA+dqPQ36z6gK9tH2xjeJknpf4OUCmZeBWVZGmQ
vNeU4RQHWevEiLOdc2SK2wWUNdprRQX3MbEeIaECgYEA0VNGBs6VX1O4kRyqrTf9
WRfOpvA27zX5WC5tRL9mVjwAsOdY3Y5Yn+rt/DeY+G9eTpbVExBfo3JeUyk8uv2R
lO0sGoXl9WA4DfzOSBUa0KeT8sSQuCtL2vFOjpkWENUvP+EP/Kqv+K262rY43YDc
NKr40h9wV9osDX4PJL9ReQ0CgYEAwrfWPKpDMz2PTY4W6cTt8DwDJTphAmekoET2
foIE9xSIEOf8zlOb7KdpbE87RGKkD4CZg/99XvGhuG4Umj56tC5A7X2gDsdt29sr
pa1sH6jFbpNz0Q/i1DUcoqDqWGqvQdVAvA7yDyCxUyliNhp3ZDlQVj2wy4hV7kYo
D3dugwECgYEAxcYpIfNY+q454w5uZoFkXGj6fbpe0wvaN7c8LLNTiLYPJGY/FbSC
pU7DiSS3yLOdrPoyaiSUFo8hfgLBkkU0/77zodc3XffScr3brxkBknicOueFf8Bf
8XHf/bBwH7hSxL0AxRtb0gD7Ajnwd+ahk+RLMIopG6AnhAfNDB28Jm4=
-----END RSA PRIVATE KEY-----`)
)

type fakeManager struct {
	cert atomic.Value
}

func (f *fakeManager) SetCertificateSigningRequestClient(certificatesclient.CertificateSigningRequestInterface) error {
	return nil
}

func (f *fakeManager) Start() {}

func (f *fakeManager) Current() *tls.Certificate {
	if val := f.cert.Load(); val != nil {
		return val.(*tls.Certificate)
	}
	return nil
}

func (f *fakeManager) setCurrent(cert *tls.Certificate) {
	f.cert.Store(cert)
}

func TestUpdateTransport(t *testing.T) {
	m := new(fakeManager)
	m.setCurrent(client1CertData.certificate)

	stop := make(chan struct{})
	defer close(stop)

	lastSeenLeafCert := new(atomic.Value) // Always *x509.Certificate

	lastSerialNumber := func() *big.Int {
		if cert := lastSeenLeafCert.Load(); cert != nil {
			return cert.(*x509.Certificate).SerialNumber
		}
		return big.NewInt(0)
	}

	h := func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) != 0 {
			lastSeenLeafCert.Store(r.TLS.PeerCertificates[0])
		}
		w.Write([]byte(`{}`))
	}

	s := httptest.NewUnstartedServer(http.HandlerFunc(h))
	s.TLS = &tls.Config{
		Certificates: []tls.Certificate{*serverCertData.certificate},
		ClientAuth:   tls.RequestClientCert,
	}
	s.StartTLS()
	defer s.Close()

	c := &rest.Config{
		Host: s.URL,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: caCertData.certificatePEM,
		},
		ContentConfig: rest.ContentConfig{
			NegotiatedSerializer: serializer.NegotiatedSerializerWrapper(runtime.SerializerInfo{}),
		},
	}

	// Check for a new cert every 10 milliseconds
	if err := updateTransport(stop, 10*time.Millisecond, c, m); err != nil {
		t.Fatal(err)
	}

	client, err := rest.UnversionedRESTClientFor(c)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.Get().Do().Error(); err != nil {
		t.Fatal(err)
	}
	firstCertSerial := lastSerialNumber()

	m.setCurrent(client2CertData.certificate)
	for i := 0; i < 5; i++ {
		time.Sleep(time.Millisecond * 10)
		client.Get().Do()
		if firstCertSerial.Cmp(lastSerialNumber()) != 0 {
			// Certificate changed!
			return
		}
	}

	t.Errorf("certificate rotated but client never reconnected with new cert")
}
