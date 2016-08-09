/*
Copyright 2014 The Kubernetes Authors.

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

package x509

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"testing"
	"time"

	"k8s.io/kubernetes/pkg/auth/user"
)

const (
	rootCACert = `-----BEGIN CERTIFICATE-----
MIIDOTCCAqKgAwIBAgIJAOoObf5kuGgZMA0GCSqGSIb3DQEBBQUAMGcxCzAJBgNV
BAYTAlVTMREwDwYDVQQIEwhNeSBTdGF0ZTEQMA4GA1UEBxMHTXkgQ2l0eTEPMA0G
A1UEChMGTXkgT3JnMRAwDgYDVQQLEwdNeSBVbml0MRAwDgYDVQQDEwdST09UIENB
MB4XDTE0MTIwODIwMjU1N1oXDTI0MTIwNTIwMjU1N1owZzELMAkGA1UEBhMCVVMx
ETAPBgNVBAgTCE15IFN0YXRlMRAwDgYDVQQHEwdNeSBDaXR5MQ8wDQYDVQQKEwZN
eSBPcmcxEDAOBgNVBAsTB015IFVuaXQxEDAOBgNVBAMTB1JPT1QgQ0EwgZ8wDQYJ
KoZIhvcNAQEBBQADgY0AMIGJAoGBAMfcayGpuF4vwrP8SXKDMCTJ9HV1cvb1NYEc
UgKF0RtcWpK+i0jvhcEs0TPDZIwLSwFw6UMEt5xy4LUlv1K/SHGY3Ym3m/TXMnB9
gkfrbWlY9LBIm4oVXwrPWyNIe74qAh1Oi03J1492uUPdHhcEmf01RIP6IIqIDuDL
xNNggeIrAgMBAAGjgewwgekwHQYDVR0OBBYEFD3w9zA9O+s6VWj69UPJx6zhPxB4
MIGZBgNVHSMEgZEwgY6AFD3w9zA9O+s6VWj69UPJx6zhPxB4oWukaTBnMQswCQYD
VQQGEwJVUzERMA8GA1UECBMITXkgU3RhdGUxEDAOBgNVBAcTB015IENpdHkxDzAN
BgNVBAoTBk15IE9yZzEQMA4GA1UECxMHTXkgVW5pdDEQMA4GA1UEAxMHUk9PVCBD
QYIJAOoObf5kuGgZMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMBEGCWCGSAGG
+EIBAQQEAwIBBjANBgkqhkiG9w0BAQUFAAOBgQBSrJjMevHUgBKkjaSyeKhOqd8V
XlbA//N/mtJTD3eD/HUZBgyMcBH+sk6hnO8N9ICHtndkTrCElME9N3JA+wg2fHLW
Lj09yrFm7u/0Wd+lcnBnczzoMDhlOjyVqsgIMhisFEw1VVaMoHblYnzY0B+oKNnu
H9oc7u5zhTGXeV8WPg==
-----END CERTIFICATE-----
`

	selfSignedCert = `-----BEGIN CERTIFICATE-----
MIIDEzCCAnygAwIBAgIJAMaPaFbGgJN+MA0GCSqGSIb3DQEBBQUAMGUxCzAJBgNV
BAYTAlVTMREwDwYDVQQIEwhNeSBTdGF0ZTEQMA4GA1UEBxMHTXkgQ2l0eTEPMA0G
A1UEChMGTXkgT3JnMRAwDgYDVQQLEwdNeSBVbml0MQ4wDAYDVQQDEwVzZWxmMTAe
Fw0xNDEyMDgyMDI1NThaFw0yNDEyMDUyMDI1NThaMGUxCzAJBgNVBAYTAlVTMREw
DwYDVQQIEwhNeSBTdGF0ZTEQMA4GA1UEBxMHTXkgQ2l0eTEPMA0GA1UEChMGTXkg
T3JnMRAwDgYDVQQLEwdNeSBVbml0MQ4wDAYDVQQDEwVzZWxmMTCBnzANBgkqhkiG
9w0BAQEFAAOBjQAwgYkCgYEA2NAe5AE//Uccy/HSqr4TBhzSe4QD5NYOWuTSKVeX
LLJ0IK2SD3PfnFM/Y0wERx6ORZPGxM0ByPO1RgZe14uFSPEdnD2WTx4lcALK9Jci
IrsvGRyMH0ZT6Q+35ScchAOdOJJYcvXEWf/heZauogzNQAGskwZdYxQB4zwC/es/
EE0CAwEAAaOByjCBxzAdBgNVHQ4EFgQUfKsCqEU/sCgvcZFSonHu2UArQ3EwgZcG
A1UdIwSBjzCBjIAUfKsCqEU/sCgvcZFSonHu2UArQ3GhaaRnMGUxCzAJBgNVBAYT
AlVTMREwDwYDVQQIEwhNeSBTdGF0ZTEQMA4GA1UEBxMHTXkgQ2l0eTEPMA0GA1UE
ChMGTXkgT3JnMRAwDgYDVQQLEwdNeSBVbml0MQ4wDAYDVQQDEwVzZWxmMYIJAMaP
aFbGgJN+MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAxpo9Nyp4d3TT
FnEC4erqQGgbc15fOF47J7bgXxsKK8o8oR/CzQ+08KhoDn3WgV39rEfX2jENDdWp
ze3kOoP+iWSmTySHMSKVMppp0Xnls6t38mrsXtPuY8fGD2GS6VllaizMqc3wShNK
4HADGF3q5z8hZYSV9ICQYHu5T9meF8M=
-----END CERTIFICATE-----
`

	clientCNCert = `Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=My State, L=My City, O=My Org, OU=My Unit, CN=ROOT CA
        Validity
            Not Before: Dec  8 20:25:58 2014 GMT
            Not After : Dec  5 20:25:58 2024 GMT
        Subject: C=US, ST=My State, L=My City, O=My Org, OU=My Unit, CN=client_cn
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:a5:30:b3:2b:c0:bd:cb:29:cf:e2:d8:fd:68:b0:
                    03:c3:a6:3b:1b:ec:36:73:a1:52:5d:27:ee:02:35:
                    5c:51:ed:3d:3b:54:d7:11:f5:38:94:ee:fd:cc:0c:
                    22:a8:f8:8e:11:2f:7c:43:5a:aa:07:3f:95:4f:50:
                    22:7d:aa:e2:5d:2a:90:3d:02:1a:5b:d2:cf:3f:fb:
                    dc:58:32:c5:ce:2f:81:58:31:20:eb:35:d3:53:d3:
                    42:47:c2:13:68:93:62:58:b6:46:60:48:17:df:d2:
                    8c:c3:40:47:cf:67:ea:27:0f:09:78:e9:d5:2a:64:
                    1e:c4:33:5a:d6:0d:7a:79:93
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Comment: 
                OpenSSL Generated Certificate
            X509v3 Subject Key Identifier: 
                E7:FB:1F:45:F0:71:77:AF:8C:10:4A:0A:42:03:F5:1F:1F:07:CF:DF
            X509v3 Authority Key Identifier: 
                keyid:3D:F0:F7:30:3D:3B:EB:3A:55:68:FA:F5:43:C9:C7:AC:E1:3F:10:78
                DirName:/C=US/ST=My State/L=My City/O=My Org/OU=My Unit/CN=ROOT CA
                serial:EA:0E:6D:FE:64:B8:68:19

            X509v3 Subject Alternative Name: 
                <EMPTY>

            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            Netscape Cert Type: 
                SSL Client
    Signature Algorithm: sha256WithRSAEncryption
         08:bc:b4:80:a5:3b:be:9a:78:f9:47:3f:c0:2d:75:e3:10:89:
         61:b1:6a:dd:f4:a4:c4:6a:d3:6f:27:30:7f:2d:07:78:d9:12:
         03:bc:a5:44:68:f3:10:bc:aa:32:e3:3f:6a:16:12:25:eb:82:
         ac:ae:30:ef:0d:be:87:11:13:e7:2f:78:69:67:36:62:ba:aa:
         51:8a:ee:6e:1e:ca:35:75:95:25:2d:db:e6:cb:71:70:95:25:
         76:99:13:02:57:99:56:25:a3:33:55:a2:6a:30:87:8b:97:e6:
         68:f3:c1:37:3c:c1:14:26:90:a0:dd:d3:02:3a:e9:c2:9e:59:
         d2:44
-----BEGIN CERTIFICATE-----
MIIDczCCAtygAwIBAgIBATANBgkqhkiG9w0BAQsFADBnMQswCQYDVQQGEwJVUzER
MA8GA1UECBMITXkgU3RhdGUxEDAOBgNVBAcTB015IENpdHkxDzANBgNVBAoTBk15
IE9yZzEQMA4GA1UECxMHTXkgVW5pdDEQMA4GA1UEAxMHUk9PVCBDQTAeFw0xNDEy
MDgyMDI1NThaFw0yNDEyMDUyMDI1NThaMGkxCzAJBgNVBAYTAlVTMREwDwYDVQQI
EwhNeSBTdGF0ZTEQMA4GA1UEBxMHTXkgQ2l0eTEPMA0GA1UEChMGTXkgT3JnMRAw
DgYDVQQLEwdNeSBVbml0MRIwEAYDVQQDFAljbGllbnRfY24wgZ8wDQYJKoZIhvcN
AQEBBQADgY0AMIGJAoGBAKUwsyvAvcspz+LY/WiwA8OmOxvsNnOhUl0n7gI1XFHt
PTtU1xH1OJTu/cwMIqj4jhEvfENaqgc/lU9QIn2q4l0qkD0CGlvSzz/73Fgyxc4v
gVgxIOs101PTQkfCE2iTYli2RmBIF9/SjMNAR89n6icPCXjp1SpkHsQzWtYNenmT
AgMBAAGjggErMIIBJzAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NM
IEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU5/sfRfBxd6+MEEoKQgP1
Hx8Hz98wgZkGA1UdIwSBkTCBjoAUPfD3MD076zpVaPr1Q8nHrOE/EHiha6RpMGcx
CzAJBgNVBAYTAlVTMREwDwYDVQQIEwhNeSBTdGF0ZTEQMA4GA1UEBxMHTXkgQ2l0
eTEPMA0GA1UEChMGTXkgT3JnMRAwDgYDVQQLEwdNeSBVbml0MRAwDgYDVQQDEwdS
T09UIENBggkA6g5t/mS4aBkwCQYDVR0RBAIwADATBgNVHSUEDDAKBggrBgEFBQcD
AjARBglghkgBhvhCAQEEBAMCB4AwDQYJKoZIhvcNAQELBQADgYEACLy0gKU7vpp4
+Uc/wC114xCJYbFq3fSkxGrTbycwfy0HeNkSA7ylRGjzELyqMuM/ahYSJeuCrK4w
7w2+hxET5y94aWc2YrqqUYrubh7KNXWVJS3b5stxcJUldpkTAleZViWjM1WiajCH
i5fmaPPBNzzBFCaQoN3TAjrpwp5Z0kQ=
-----END CERTIFICATE-----`

	clientDNSCert = `Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4 (0x4)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=My State, L=My City, O=My Org, OU=My Unit, CN=ROOT CA
        Validity
            Not Before: Dec  8 20:25:58 2014 GMT
            Not After : Dec  5 20:25:58 2024 GMT
        Subject: C=US, ST=My State, L=My City, O=My Org, OU=My Unit, CN=client_dns
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:b0:6d:16:6a:fc:28:f7:dc:da:2c:a8:e4:0c:27:
                    3c:27:ce:ae:d5:72:d9:3c:eb:af:3d:a3:83:98:5b:
                    85:d8:68:f4:bd:53:57:d2:ad:e8:71:b1:18:8e:ae:
                    37:8e:02:9c:b2:6c:92:09:cc:5e:e6:74:a1:4b:e1:
                    50:41:08:9a:5e:d4:20:0b:6f:c7:c0:34:a8:e6:be:
                    77:1d:43:1f:2c:df:dc:ca:9d:1a:0a:9f:a3:6e:0a:
                    60:f1:6d:d9:7f:f0:f1:ea:66:9d:4c:f3:de:62:af:
                    b1:92:70:f1:bb:8a:81:f4:9c:3c:b8:c9:e8:04:18:
                    70:2f:77:74:48:d9:cd:e5:af
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Comment: 
                OpenSSL Generated Certificate
            X509v3 Subject Key Identifier: 
                6E:A3:F6:01:52:79:4D:46:78:3C:D0:AB:4A:75:96:AC:7D:6C:08:BE
            X509v3 Authority Key Identifier: 
                keyid:3D:F0:F7:30:3D:3B:EB:3A:55:68:FA:F5:43:C9:C7:AC:E1:3F:10:78
                DirName:/C=US/ST=My State/L=My City/O=My Org/OU=My Unit/CN=ROOT CA
                serial:EA:0E:6D:FE:64:B8:68:19

            X509v3 Subject Alternative Name: 
                DNS:client_dns.example.com
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            Netscape Cert Type: 
                SSL Client
    Signature Algorithm: sha256WithRSAEncryption
         69:20:83:0f:16:f8:b6:f5:04:98:56:a4:b2:67:32:e0:82:80:
         da:8e:54:06:94:96:cd:56:eb:90:4c:f4:3c:50:80:6a:25:ac:
         3d:e2:81:05:e4:89:2b:55:63:9a:2d:4a:da:3b:c4:97:5e:1a:
         e9:6f:83:b8:05:4a:dc:bd:ab:b0:a0:75:d0:1e:b5:c5:8d:f3:
         f6:92:f1:52:d2:81:67:fc:6f:74:ee:49:37:73:08:bc:f5:26:
         86:67:f5:82:04:ff:db:5a:9f:f9:6b:df:2f:f5:75:61:f2:a5:
         91:0b:05:56:5b:e8:d1:36:d7:56:7a:ed:7d:e5:5f:2a:08:87:
         c2:48
-----BEGIN CERTIFICATE-----
MIIDjDCCAvWgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBnMQswCQYDVQQGEwJVUzER
MA8GA1UECBMITXkgU3RhdGUxEDAOBgNVBAcTB015IENpdHkxDzANBgNVBAoTBk15
IE9yZzEQMA4GA1UECxMHTXkgVW5pdDEQMA4GA1UEAxMHUk9PVCBDQTAeFw0xNDEy
MDgyMDI1NThaFw0yNDEyMDUyMDI1NThaMGoxCzAJBgNVBAYTAlVTMREwDwYDVQQI
EwhNeSBTdGF0ZTEQMA4GA1UEBxMHTXkgQ2l0eTEPMA0GA1UEChMGTXkgT3JnMRAw
DgYDVQQLEwdNeSBVbml0MRMwEQYDVQQDFApjbGllbnRfZG5zMIGfMA0GCSqGSIb3
DQEBAQUAA4GNADCBiQKBgQCwbRZq/Cj33NosqOQMJzwnzq7Vctk86689o4OYW4XY
aPS9U1fSrehxsRiOrjeOApyybJIJzF7mdKFL4VBBCJpe1CALb8fANKjmvncdQx8s
39zKnRoKn6NuCmDxbdl/8PHqZp1M895ir7GScPG7ioH0nDy4yegEGHAvd3RI2c3l
rwIDAQABo4IBQzCCAT8wCQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYdT3BlblNT
TCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFG6j9gFSeU1GeDzQq0p1
lqx9bAi+MIGZBgNVHSMEgZEwgY6AFD3w9zA9O+s6VWj69UPJx6zhPxB4oWukaTBn
MQswCQYDVQQGEwJVUzERMA8GA1UECBMITXkgU3RhdGUxEDAOBgNVBAcTB015IENp
dHkxDzANBgNVBAoTBk15IE9yZzEQMA4GA1UECxMHTXkgVW5pdDEQMA4GA1UEAxMH
Uk9PVCBDQYIJAOoObf5kuGgZMCEGA1UdEQQaMBiCFmNsaWVudF9kbnMuZXhhbXBs
ZS5jb20wEwYDVR0lBAwwCgYIKwYBBQUHAwIwEQYJYIZIAYb4QgEBBAQDAgeAMA0G
CSqGSIb3DQEBCwUAA4GBAGkggw8W+Lb1BJhWpLJnMuCCgNqOVAaUls1W65BM9DxQ
gGolrD3igQXkiStVY5otSto7xJdeGulvg7gFSty9q7CgddAetcWN8/aS8VLSgWf8
b3TuSTdzCLz1JoZn9YIE/9tan/lr3y/1dWHypZELBVZb6NE211Z67X3lXyoIh8JI
-----END CERTIFICATE-----`

	clientEmailCert = `Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=My State, L=My City, O=My Org, OU=My Unit, CN=ROOT CA
        Validity
            Not Before: Dec  8 20:25:58 2014 GMT
            Not After : Dec  5 20:25:58 2024 GMT
        Subject: C=US, ST=My State, L=My City, O=My Org, OU=My Unit, CN=client_email
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:bf:f3:c3:d7:50:d5:64:d6:d2:e3:6c:bb:7e:5d:
                    4b:41:63:76:9c:c4:c8:33:9a:37:ee:68:24:1e:26:
                    cf:de:57:79:d6:dc:53:b6:da:12:c6:c0:95:7d:69:
                    b8:af:1d:4e:8f:a5:83:8b:22:78:e3:94:cc:6e:fe:
                    24:e2:05:91:ed:1c:01:b7:e1:53:91:aa:51:53:7a:
                    55:6e:fe:0c:ef:c1:66:70:12:0c:85:94:95:c6:3e:
                    f5:35:58:4d:3f:11:b1:5a:d6:ec:a1:f5:21:c1:e6:
                    1f:c1:91:5b:67:89:25:2a:e3:86:27:6b:d8:31:7b:
                    f1:0d:83:c7:f2:68:70:f0:23
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Comment: 
                OpenSSL Generated Certificate
            X509v3 Subject Key Identifier: 
                76:22:99:CD:3D:BA:90:62:0F:BE:E7:5B:57:8D:31:1D:25:27:C6:6A
            X509v3 Authority Key Identifier: 
                keyid:3D:F0:F7:30:3D:3B:EB:3A:55:68:FA:F5:43:C9:C7:AC:E1:3F:10:78
                DirName:/C=US/ST=My State/L=My City/O=My Org/OU=My Unit/CN=ROOT CA
                serial:EA:0E:6D:FE:64:B8:68:19

            X509v3 Subject Alternative Name: 
                email:client_email@example.com
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            Netscape Cert Type: 
                SSL Client
    Signature Algorithm: sha256WithRSAEncryption
         80:70:19:d2:5c:c1:cf:d2:b6:e5:0e:76:cd:8f:c2:8d:a8:19:
         07:86:22:3f:a4:b1:98:c6:98:c1:dc:f8:99:5b:20:5c:6d:17:
         6b:fa:8b:4c:1b:86:14:b4:71:f7:41:22:03:ca:ec:2c:cd:ae:
         77:93:bd:08:06:8c:3c:06:ce:04:2c:b1:ce:79:20:0d:d5:01:
         1c:bd:66:60:38:db:4f:ad:dc:a6:33:8f:07:af:e6:bd:1c:27:
         4b:93:6a:4f:59:e3:cf:df:ff:87:f1:af:02:ad:50:06:f9:50:
         c7:59:87:bc:0c:e6:66:cd:d1:c8:df:e6:15:b2:21:b3:04:86:
         8c:89
-----BEGIN CERTIFICATE-----
MIIDkDCCAvmgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBnMQswCQYDVQQGEwJVUzER
MA8GA1UECBMITXkgU3RhdGUxEDAOBgNVBAcTB015IENpdHkxDzANBgNVBAoTBk15
IE9yZzEQMA4GA1UECxMHTXkgVW5pdDEQMA4GA1UEAxMHUk9PVCBDQTAeFw0xNDEy
MDgyMDI1NThaFw0yNDEyMDUyMDI1NThaMGwxCzAJBgNVBAYTAlVTMREwDwYDVQQI
EwhNeSBTdGF0ZTEQMA4GA1UEBxMHTXkgQ2l0eTEPMA0GA1UEChMGTXkgT3JnMRAw
DgYDVQQLEwdNeSBVbml0MRUwEwYDVQQDFAxjbGllbnRfZW1haWwwgZ8wDQYJKoZI
hvcNAQEBBQADgY0AMIGJAoGBAL/zw9dQ1WTW0uNsu35dS0FjdpzEyDOaN+5oJB4m
z95XedbcU7baEsbAlX1puK8dTo+lg4sieOOUzG7+JOIFke0cAbfhU5GqUVN6VW7+
DO/BZnASDIWUlcY+9TVYTT8RsVrW7KH1IcHmH8GRW2eJJSrjhidr2DF78Q2Dx/Jo
cPAjAgMBAAGjggFFMIIBQTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVu
U1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUdiKZzT26kGIPvudb
V40xHSUnxmowgZkGA1UdIwSBkTCBjoAUPfD3MD076zpVaPr1Q8nHrOE/EHiha6Rp
MGcxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhNeSBTdGF0ZTEQMA4GA1UEBxMHTXkg
Q2l0eTEPMA0GA1UEChMGTXkgT3JnMRAwDgYDVQQLEwdNeSBVbml0MRAwDgYDVQQD
EwdST09UIENBggkA6g5t/mS4aBkwIwYDVR0RBBwwGoEYY2xpZW50X2VtYWlsQGV4
YW1wbGUuY29tMBMGA1UdJQQMMAoGCCsGAQUFBwMCMBEGCWCGSAGG+EIBAQQEAwIH
gDANBgkqhkiG9w0BAQsFAAOBgQCAcBnSXMHP0rblDnbNj8KNqBkHhiI/pLGYxpjB
3PiZWyBcbRdr+otMG4YUtHH3QSIDyuwsza53k70IBow8Bs4ELLHOeSAN1QEcvWZg
ONtPrdymM48Hr+a9HCdLk2pPWePP3/+H8a8CrVAG+VDHWYe8DOZmzdHI3+YVsiGz
BIaMiQ==
-----END CERTIFICATE-----
`

	serverCert = `Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 7 (0x7)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=My State, L=My City, O=My Org, OU=My Unit, CN=ROOT CA
        Validity
            Not Before: Dec  8 20:25:58 2014 GMT
            Not After : Dec  5 20:25:58 2024 GMT
        Subject: C=US, ST=My State, L=My City, O=My Org, OU=My Unit, CN=127.0.0.1
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:e2:50:d9:1c:ff:03:34:0d:f8:b4:0c:08:70:fc:
                    2a:27:2f:42:c9:4b:90:f2:a7:f2:7c:8c:ec:58:a5:
                    0f:49:29:0c:77:b5:aa:0a:aa:b7:71:e7:2d:0e:fb:
                    73:2c:88:de:70:69:df:d1:b0:7f:3b:2d:28:99:2d:
                    f1:43:93:13:aa:c9:98:16:05:05:fb:80:64:7b:11:
                    19:44:b7:5a:8c:83:20:6f:68:73:4f:ec:78:c2:73:
                    de:96:68:30:ce:2a:04:03:22:80:21:26:cc:7e:d6:
                    ec:b5:58:a7:41:bb:ae:fc:2c:29:6a:d1:3a:aa:b9:
                    2f:88:f5:62:d8:8e:69:f4:19
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Comment: 
                OpenSSL Generated Certificate
            X509v3 Subject Key Identifier: 
                36:A1:0C:B2:28:0C:77:6C:7F:96:90:11:CA:19:AF:67:1E:92:17:08
            X509v3 Authority Key Identifier: 
                keyid:3D:F0:F7:30:3D:3B:EB:3A:55:68:FA:F5:43:C9:C7:AC:E1:3F:10:78
                DirName:/C=US/ST=My State/L=My City/O=My Org/OU=My Unit/CN=ROOT CA
                serial:EA:0E:6D:FE:64:B8:68:19

            X509v3 Subject Alternative Name: 
                <EMPTY>

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            Netscape Cert Type: 
                SSL Server
    Signature Algorithm: sha256WithRSAEncryption
         a9:dd:3d:64:e5:e2:fb:7e:2e:ce:52:7a:85:1d:62:0b:ec:ca:
         1d:78:51:d1:f7:13:36:1c:27:3f:69:59:27:5f:89:ac:41:5e:
         65:c6:ae:dc:18:60:18:85:5b:bb:9a:76:93:df:60:47:96:97:
         58:61:34:98:59:46:ea:d4:ad:01:6c:f7:4e:6c:9d:72:26:4d:
         76:21:1b:7a:a1:f0:e6:e6:88:61:68:f5:cc:2e:40:76:f1:57:
         04:5b:9e:d2:88:c8:ac:9e:49:b5:b4:d6:71:c1:fd:d8:b8:0f:
         c7:1a:9c:f3:3f:cc:11:60:ef:54:3a:3d:b8:8d:09:80:fe:be:
         f9:ef
-----BEGIN CERTIFICATE-----
MIIDczCCAtygAwIBAgIBBzANBgkqhkiG9w0BAQsFADBnMQswCQYDVQQGEwJVUzER
MA8GA1UECBMITXkgU3RhdGUxEDAOBgNVBAcTB015IENpdHkxDzANBgNVBAoTBk15
IE9yZzEQMA4GA1UECxMHTXkgVW5pdDEQMA4GA1UEAxMHUk9PVCBDQTAeFw0xNDEy
MDgyMDI1NThaFw0yNDEyMDUyMDI1NThaMGkxCzAJBgNVBAYTAlVTMREwDwYDVQQI
EwhNeSBTdGF0ZTEQMA4GA1UEBxMHTXkgQ2l0eTEPMA0GA1UEChMGTXkgT3JnMRAw
DgYDVQQLEwdNeSBVbml0MRIwEAYDVQQDEwkxMjcuMC4wLjEwgZ8wDQYJKoZIhvcN
AQEBBQADgY0AMIGJAoGBAOJQ2Rz/AzQN+LQMCHD8KicvQslLkPKn8nyM7FilD0kp
DHe1qgqqt3HnLQ77cyyI3nBp39GwfzstKJkt8UOTE6rJmBYFBfuAZHsRGUS3WoyD
IG9oc0/seMJz3pZoMM4qBAMigCEmzH7W7LVYp0G7rvwsKWrROqq5L4j1YtiOafQZ
AgMBAAGjggErMIIBJzAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NM
IEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUNqEMsigMd2x/lpARyhmv
Zx6SFwgwgZkGA1UdIwSBkTCBjoAUPfD3MD076zpVaPr1Q8nHrOE/EHiha6RpMGcx
CzAJBgNVBAYTAlVTMREwDwYDVQQIEwhNeSBTdGF0ZTEQMA4GA1UEBxMHTXkgQ2l0
eTEPMA0GA1UEChMGTXkgT3JnMRAwDgYDVQQLEwdNeSBVbml0MRAwDgYDVQQDEwdS
T09UIENBggkA6g5t/mS4aBkwCQYDVR0RBAIwADATBgNVHSUEDDAKBggrBgEFBQcD
ATARBglghkgBhvhCAQEEBAMCBkAwDQYJKoZIhvcNAQELBQADgYEAqd09ZOXi+34u
zlJ6hR1iC+zKHXhR0fcTNhwnP2lZJ1+JrEFeZcau3BhgGIVbu5p2k99gR5aXWGE0
mFlG6tStAWz3TmydciZNdiEbeqHw5uaIYWj1zC5AdvFXBFue0ojIrJ5JtbTWccH9
2LgPxxqc8z/MEWDvVDo9uI0JgP6++e8=
-----END CERTIFICATE-----
`

	/*
		openssl genrsa -out ca.key 4096
		openssl req -new -x509 -days 36500 \
		    -sha256 -key ca.key -extensions v3_ca \
		    -out ca.crt \
		    -subj "/C=US/ST=My State/L=My City/O=My Org/OU=My Unit 1/OU=My Unit 2/CN=ROOT CA WITH GROUPS"
		openssl x509 -in ca.crt -text
	*/

	// A certificate with multiple organizational units.
	caWithGroups = `Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            dc:2d:10:d3:e1:e1:bf:38
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=My State, L=My City, O=My Org, OU=My Unit 1, OU=My Unit 2, CN=ROOT CA WITH GROUPS
        Validity
            Not Before: Aug  9 17:29:06 2016 GMT
            Not After : Jul 16 17:29:06 2116 GMT
        Subject: C=US, ST=My State, L=My City, O=My Org, OU=My Unit 1, OU=My Unit 2, CN=ROOT CA WITH GROUPS
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:e9:bb:55:1c:aa:a8:6b:5e:76:73:cc:12:4f:90:
                    bf:ae:cc:a1:55:42:8b:a8:f3:10:d5:91:cc:51:10:
                    e8:5a:63:5c:72:59:1a:e9:89:5b:c8:e2:fd:07:a5:
                    f7:fe:98:43:5e:4b:0d:eb:bc:c3:c8:26:68:5b:12:
                    4f:cb:3f:16:22:e2:01:0a:00:aa:0f:ed:28:9c:38:
                    22:37:d4:8b:2c:26:43:2e:2c:0d:d7:dd:9e:36:e6:
                    66:29:9e:27:cb:6c:92:05:a0:5b:a5:2a:e1:d4:3c:
                    60:89:48:25:f9:3e:60:86:ef:27:4d:46:0a:63:4b:
                    34:a3:7c:43:46:4c:27:c5:e7:0e:2c:58:50:20:5e:
                    2c:4e:db:e7:7d:f6:e4:eb:7f:d7:8b:5d:82:55:4e:
                    43:f5:d4:56:90:3b:c6:33:8d:bb:7e:87:09:24:6d:
                    b5:f9:1e:43:55:74:42:1c:bc:d6:24:f8:7e:82:0f:
                    99:66:1f:c5:2e:bd:29:91:27:c9:c3:e7:8d:d9:93:
                    03:23:8a:1a:56:2c:23:02:2b:b4:1d:0e:7d:61:83:
                    b7:33:69:d3:f7:b7:46:05:44:c8:19:49:b4:73:3d:
                    50:c8:a7:d0:01:ec:23:31:aa:75:00:3a:9c:fb:79:
                    8f:1b:13:6b:eb:90:1e:ae:c2:23:f1:b8:15:ed:eb:
                    8d:b1:7c:42:d7:f5:59:32:6d:4a:c4:e3:03:c4:e7:
                    ae:88:2f:dd:02:36:20:54:dd:53:20:96:fe:d5:e7:
                    1e:12:50:17:02:33:db:a3:0d:9c:2a:45:7d:29:85:
                    15:f5:5a:6f:ed:d8:9b:6e:84:67:6e:b8:00:bb:48:
                    11:b6:6a:6b:69:1f:8b:49:f8:13:ea:e5:f5:0e:36:
                    37:c8:62:b5:da:f6:9d:98:5c:c8:93:0b:96:a9:f6:
                    9e:ce:bd:1b:50:70:b6:7e:88:ad:9d:1d:26:93:46:
                    d7:5b:4a:6d:dc:64:a0:17:4a:15:5b:16:06:c9:0b:
                    e8:48:de:90:ae:78:e6:ea:ee:d7:f6:13:d5:94:c3:
                    dd:d1:0e:bf:d6:b2:c2:a0:93:c0:98:c5:cd:1c:a3:
                    9c:13:4f:2a:c8:14:3a:68:54:82:9f:cf:7a:0a:1f:
                    da:df:37:68:79:8d:9d:c6:e1:3f:05:20:af:5d:37:
                    aa:8b:80:26:fc:ac:54:6e:83:ef:cb:3d:8f:5f:21:
                    a2:18:f7:05:03:34:c6:f4:a5:39:f4:9f:fb:70:6f:
                    a9:d7:e0:e1:89:9a:63:ef:38:94:5c:c9:ee:65:46:
                    1f:cc:c9:f3:6f:2c:a5:74:1b:c5:a9:92:2a:50:00:
                    40:5b:79:4d:9d:b5:26:b8:7e:1c:33:5e:66:49:f4:
                    7c:d7:75
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                DC:F8:7E:05:FD:34:C0:AA:86:42:40:9F:3C:39:90:73:AC:88:D5:45
            X509v3 Authority Key Identifier: 
                keyid:DC:F8:7E:05:FD:34:C0:AA:86:42:40:9F:3C:39:90:73:AC:88:D5:45

            X509v3 Basic Constraints: 
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
         d9:cc:d3:7a:97:2f:49:1e:7a:95:76:77:c9:e8:47:15:00:60:
         a3:4e:e0:5a:dd:d3:77:49:80:87:5d:b4:97:da:1d:38:06:9c:
         5d:ae:61:2d:7d:81:83:be:ca:f1:1d:95:23:5b:ad:f8:93:e2:
         a4:db:4c:6f:d2:2b:e0:9b:b7:90:9a:cd:7d:fb:14:8d:6f:d9:
         64:90:97:95:00:10:a7:cb:92:40:8c:fa:f8:b0:d9:cf:a9:96:
         c0:81:28:27:44:9a:fb:f5:c2:70:bc:6e:16:bb:a0:b7:cb:6d:
         dd:90:52:2b:11:6e:b7:cd:70:5a:c5:65:92:69:35:6c:16:05:
         c0:ca:5e:15:4d:8b:f6:fa:5f:26:2e:27:78:f6:9c:32:ea:5c:
         93:aa:76:9c:ae:a3:71:6f:c4:6f:82:2d:67:89:23:42:f8:24:
         59:98:88:5f:a8:f9:30:e7:33:94:a4:97:e5:58:38:fa:7a:b9:
         0f:e7:d4:50:0c:48:4c:5e:89:c5:11:95:2b:da:ea:64:73:51:
         13:f2:c4:94:9f:83:e4:b8:a3:58:1a:90:4b:af:b3:a2:66:0f:
         8f:6b:f8:5a:2c:fa:7c:bf:7d:44:af:f0:4f:27:07:c5:6b:22:
         0d:f4:04:f6:77:f2:57:af:0e:7d:89:a7:76:c4:99:ec:6c:5b:
         02:27:cc:c1:e3:e3:13:c1:f9:78:66:5c:4f:46:30:dd:08:17:
         62:25:3a:3b:90:80:ff:f4:51:73:1e:b9:61:82:e1:fb:f0:18:
         77:08:a4:4a:13:18:ee:a6:12:f9:d9:13:7a:e6:c8:77:2e:e3:
         b7:cc:2b:d0:39:5f:76:91:92:db:80:ba:fa:7c:6a:51:1b:44:
         69:68:4b:a5:7f:9c:4f:60:63:07:1e:b1:ed:c0:2e:ae:a0:bf:
         64:ee:2a:0a:4f:c7:b2:fc:e5:41:a5:60:f5:4c:89:11:8e:f3:
         bb:95:71:08:f7:76:a8:51:a9:30:3c:90:80:f8:f5:a3:ea:64:
         21:1b:ac:3c:ce:8b:64:98:fc:8a:11:7b:5f:85:10:1a:53:d7:
         be:01:b7:5a:bc:80:ed:75:7d:0a:1a:6b:8a:57:f9:08:71:4d:
         11:e9:31:54:5a:e1:a1:05:f0:de:bc:eb:00:0a:51:8e:4e:ac:
         12:0e:c3:34:a7:9f:db:92:6a:bb:b8:31:cc:d0:73:81:8a:97:
         f7:7c:b5:4f:46:78:02:2a:cc:aa:44:19:90:dc:5f:57:25:eb:
         8f:12:85:df:1d:ef:b9:7b:c6:65:a7:47:69:b4:f6:2b:2a:86:
         bd:4b:e0:3d:66:d5:df:14:71:5a:35:ad:48:05:54:b3:23:1a:
         ff:ba:d4:0b:8a:d2:11:a7
-----BEGIN CERTIFICATE-----
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
KyqGvUvgPWbV3xRxWjWtSAVUsyMa/7rUC4rSEac=
-----END CERTIFICATE-----`
)

func TestX509(t *testing.T) {
	testCases := map[string]struct {
		Insecure bool
		Certs    []*x509.Certificate

		Opts x509.VerifyOptions
		User UserConversion

		ExpectUserName string
		ExpectGroups   []string
		ExpectOK       bool
		ExpectErr      bool
	}{
		"non-tls": {
			Insecure: true,

			ExpectOK:  false,
			ExpectErr: false,
		},

		"tls, no certs": {
			ExpectOK:  false,
			ExpectErr: false,
		},

		"self signed": {
			Opts:  getDefaultVerifyOptions(t),
			Certs: getCerts(t, selfSignedCert),
			User:  CommonNameUserConversion,

			ExpectErr: true,
		},

		"server cert": {
			Opts:  getDefaultVerifyOptions(t),
			Certs: getCerts(t, serverCert),
			User:  CommonNameUserConversion,

			ExpectErr: true,
		},
		"server cert allowing non-client cert usages": {
			Opts:  x509.VerifyOptions{Roots: getRootCertPool(t)},
			Certs: getCerts(t, serverCert),
			User:  CommonNameUserConversion,

			ExpectUserName: "127.0.0.1",
			ExpectGroups:   []string{"My Unit"},
			ExpectOK:       true,
			ExpectErr:      false,
		},

		"common name": {
			Opts:  getDefaultVerifyOptions(t),
			Certs: getCerts(t, clientCNCert),
			User:  CommonNameUserConversion,

			ExpectUserName: "client_cn",
			ExpectGroups:   []string{"My Unit"},
			ExpectOK:       true,
			ExpectErr:      false,
		},
		"ca with multiple organizational units": {
			Opts: x509.VerifyOptions{
				Roots: getRootCertPoolFor(t, caWithGroups),
			},
			Certs: getCerts(t, caWithGroups),
			User:  CommonNameUserConversion,

			ExpectUserName: "ROOT CA WITH GROUPS",
			ExpectGroups:   []string{"My Unit 1", "My Unit 2"},
			ExpectOK:       true,
			ExpectErr:      false,
		},
		"empty dns": {
			Opts:  getDefaultVerifyOptions(t),
			Certs: getCerts(t, clientCNCert),
			User:  DNSNameUserConversion,

			ExpectOK:  false,
			ExpectErr: false,
		},
		"dns": {
			Opts:  getDefaultVerifyOptions(t),
			Certs: getCerts(t, clientDNSCert),
			User:  DNSNameUserConversion,

			ExpectUserName: "client_dns.example.com",
			ExpectOK:       true,
			ExpectErr:      false,
		},

		"empty email": {
			Opts:  getDefaultVerifyOptions(t),
			Certs: getCerts(t, clientCNCert),
			User:  EmailAddressUserConversion,

			ExpectOK:  false,
			ExpectErr: false,
		},
		"email": {
			Opts:  getDefaultVerifyOptions(t),
			Certs: getCerts(t, clientEmailCert),
			User:  EmailAddressUserConversion,

			ExpectUserName: "client_email@example.com",
			ExpectOK:       true,
			ExpectErr:      false,
		},

		"custom conversion error": {
			Opts:  getDefaultVerifyOptions(t),
			Certs: getCerts(t, clientCNCert),
			User: UserConversionFunc(func(chain []*x509.Certificate) (user.Info, bool, error) {
				return nil, false, errors.New("custom error")
			}),

			ExpectOK:  false,
			ExpectErr: true,
		},
		"custom conversion success": {
			Opts:  getDefaultVerifyOptions(t),
			Certs: getCerts(t, clientCNCert),
			User: UserConversionFunc(func(chain []*x509.Certificate) (user.Info, bool, error) {
				return &user.DefaultInfo{Name: "custom"}, true, nil
			}),

			ExpectUserName: "custom",
			ExpectOK:       true,
			ExpectErr:      false,
		},

		"future cert": {
			Opts: x509.VerifyOptions{
				CurrentTime: time.Now().Add(time.Duration(-100 * time.Hour * 24 * 365)),
				Roots:       getRootCertPool(t),
			},
			Certs: getCerts(t, clientCNCert),
			User:  CommonNameUserConversion,

			ExpectOK:  false,
			ExpectErr: true,
		},
		"expired cert": {
			Opts: x509.VerifyOptions{
				CurrentTime: time.Now().Add(time.Duration(100 * time.Hour * 24 * 365)),
				Roots:       getRootCertPool(t),
			},
			Certs: getCerts(t, clientCNCert),
			User:  CommonNameUserConversion,

			ExpectOK:  false,
			ExpectErr: true,
		},
	}

	for k, testCase := range testCases {
		req, _ := http.NewRequest("GET", "/", nil)
		if !testCase.Insecure {
			req.TLS = &tls.ConnectionState{PeerCertificates: testCase.Certs}
		}

		a := New(testCase.Opts, testCase.User)

		user, ok, err := a.AuthenticateRequest(req)

		if testCase.ExpectErr && err == nil {
			t.Errorf("%s: Expected error, got none", k)
			continue
		}
		if !testCase.ExpectErr && err != nil {
			t.Errorf("%s: Got unexpected error: %v", k, err)
			continue
		}

		if testCase.ExpectOK != ok {
			t.Errorf("%s: Expected ok=%v, got %v", k, testCase.ExpectOK, ok)
			continue
		}

		if testCase.ExpectOK {
			if testCase.ExpectUserName != user.GetName() {
				t.Errorf("%s: Expected user.name=%v, got %v", k, testCase.ExpectUserName, user.GetName())
			}

			groups := user.GetGroups()
			sort.Strings(testCase.ExpectGroups)
			sort.Strings(groups)
			if !reflect.DeepEqual(testCase.ExpectGroups, groups) {
				t.Errorf("%s: Expected user.groups=%v, got %v", k, testCase.ExpectGroups, groups)
			}
		}
	}
}

func getDefaultVerifyOptions(t *testing.T) x509.VerifyOptions {
	options := DefaultVerifyOptions()
	options.Roots = getRootCertPool(t)
	return options
}

func getRootCertPool(t *testing.T) *x509.CertPool {
	return getRootCertPoolFor(t, rootCACert)
}

func getRootCertPoolFor(t *testing.T, certs ...string) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(getCert(t, cert))
	}
	return pool
}

func getCert(t *testing.T, pemData string) *x509.Certificate {
	pemBlock, _ := pem.Decode([]byte(pemData))
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Error parsing cert: %v", err)
		return nil
	}
	return cert
}

func getCerts(t *testing.T, pemData ...string) []*x509.Certificate {
	certs := make([]*x509.Certificate, 0)
	for _, pemData := range pemData {
		certs = append(certs, getCert(t, pemData))
	}
	return certs
}
