// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package keystore_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	pkix2 "github.com/dadrus/heimdall/internal/x/pkix"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

// nolint: gochecknoglobals
// generated with openssl ecparam -name prime256v1 -genkey -noout -out key.pem.
var pemPKCS1ECPrivateKey = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAcCM9VY6RRiUlz3UoywbT9yN9UlWEEWKIPqiA2D86pCoAoGCCqGSM49
AwEHoUQDQgAEPEmirqVF2KoNguFuh4GGyShM3OIZt/yD6WESlOvAJhJX6HZyOgFu
xijD/4gPFRBfs2GsfVZzSL9kH7HH0chB9w==
-----END EC PRIVATE KEY-----
`)

// nolint: gochecknoglobals
// converted with openssl pkcs8 -topk8 -in key.pem -out pkcs8.pem.
var pemPKCS8ECEncryptedPrivateKey = []byte(`
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAiJ8VMMyD9LkQICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEDM4MvufeWaeKFIyuILKBAYEgZC0
iSSw1qwqVWxIik/YWxn90MvvNCg9P1MHyF2i5w7Xp+uPFjRM4o+7PdHhRgJSnsDT
6JYTU6S5Gdl6t5JsFqhIBDYyqrs/+cegw0dSGl/B/UoZ0taNK66RKQ6wuv/VCcuY
MtusvyePIsJKGGKsTyHwla4eWpjorL+V116zP35J5x32AFIT8hCbZlLGdL5dpVU=
-----END ENCRYPTED PRIVATE KEY-----
`)

// nolint: gochecknoglobals
// converted with openssl pkcs8 -topk8 -in key.pem -out pkcs8.pem -nocrypt.
var pemPKCS8ECPrivateKey = []byte(`
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBwIz1VjpFGJSXPdS
jLBtP3I31SVYQRYog+qIDYPzqkKhRANCAAQ8SaKupUXYqg2C4W6HgYbJKEzc4hm3
/IPpYRKU68AmElfodnI6AW7GKMP/iA8VEF+zYax9VnNIv2QfscfRyEH3
-----END PRIVATE KEY-----
`)

// nolint: gochecknoglobals
// generated with openssl genrsa -out key.pem 2048.
var pemPKCS1RSAPrivateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvxc3ZHNNVafIJvYRdIZ+DDV0qDom15k97pLzcgnNjRtA/CKr
bd4M6qMUcKp6T99rEvRDWRlBEE1sTEa3OtA3tW+32pRMOzUBoUaLzPtXAxYJzzKx
lyIeRLAK8pxtOcwP0s9FQbNndmV08S0at5EZJzYLqN9yRuC+2It+5fvOUyIrcNGs
uFB52MIoy9JYWjIw2gdqjWXVRqV5SvWT4ftVjt43Lt/sjBrTiZrDSS6HpgbYw0CU
BsX0LKedLYER3SRfSKy7E/vAhOhAEINppakjFTPAtUAxTI4pSnvTxe4+9LTcqVQ4
UieQcDBFdqaLhW7kp6XpIdhyWylzzVepPBtMTwIDAQABAoIBACtNVIUTx8uIOMfz
bOMt8vRLTMMuYkzq8ejVLguCgyzdpy07ogNElUK6b9BUIWFmLHpgFb7kBSVvlgH2
6GCQfH9F8LC8eEXWbicguF9b+Uy+urxULYAlABzqk6CEqA+32UIZLAWGZQSkWwqo
AOzmGYAUNDIxaFD9buHdQoVVOV0G9Ypu2L7fadatjmAbWsd5VI888Dcps3zguMQW
RSk5z8ycebD1F0V6dgukTg6SWqOLXTM3I+XVzbdHBfXhNJ5KJ+DRCW53Oll+F8TN
miPOMMkWj6WvQJJSt+TWymEpbViTb9AOeZ+5tJfbFkr1QP14zO78aTuQMJNu4va1
Yi3VLGECgYEA8rmfsNYllb/a9hXaNdfUynjolsC59yiRMyM+6Zq6UxNGY15O0uoT
WevyjpcXc4pAhEE3tQa43TALXOJW3uYmtF49HlbB0kvj9aFTM/JOlFD3Y1DVPPpC
QrjKQFCjKJNtYRpuJ6U0skf0qdogEzPyV1hfg+V0UxYsaI1GxoOuy/ECgYEAyYqp
v+9VpV3zihzd72beVrwcVlcgqREGyGzap1J1hBHrh4eRbHfr7+aIaDjMFw7UOm8r
p7xlxO7XfmLdNL+/ULXYOYssXhWRabSmkO8K+jSe8/GdeWfFGLjHBCSj+XjUdvbj
1GiPbyKrptC2UsL8BO1XLm/kAfi4U6xzrY4U3D8CgYAnMhB2hu5E01lxea/mF/dV
xtaQWYjuP4/K+TsUkBbciXVJYJZL+t6rG63slruDveSTNtDfG7nIhhSfqDEtB29i
mwE1n/7mjbi/FpEQB2XnD3gTgp8cnLEMgzit0Be42q3EC3eUUVpEG9iHgSDC2RWe
QzgRXYE+VYtQStgOAH++kQKBgQDIfWuOZx1xKzw5eawCGvg1ml4qOfRgm3J+8WK2
rt3+qwD9ywwMtmN8PH4YB+BnU7YmBy+LZmxq8xpmPR1G+zTrqmpWHC/fzF7io/ZL
GbF249/4VrRL8MHubOp2IakJZH0fd01/oSCG8xuFD/0/6X5hvGVM6bwNhgqAGn7c
+QmhawKBgCUGxf5zYov6ZEVup06O/hlwAwMsq1vw2KPlwYMcjAKDj6rIz8mAZmT+
Yxty35glWR1l8sPN0rD9+QdEYuLY3Ov23SVxHnNKy1pGSJjTinBkfjNEBOdfDUrV
ga1bMw04tVw/6O9EEKNGaQsS6B0fzq99acgVHADvRji+eqw18x0J
-----END RSA PRIVATE KEY-----
`)

// nolint: gochecknoglobals
// converted with openssl pkcs8 -topk8 -in key.pem -out pkcs8.pem.
var pemPKCS8RSAEncryptedPrivateKey = []byte(`
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI2GK20IxuPzwCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBCR3q6ur2Vas0CfsnCyEDqoBIIE
0CUJpUEry5TTIoFmC2n/mXQAhtN6USharJQ8/Lt38DUtRqHsFaOPSqPcedzgDRNo
Dw9sIWD20l4ii5ucIn4nn69HbroCUg5y5P1i/0ldwsKJgy/FNFdVnS5ft/x5qlkO
+bpqalKd14xiNlnbT5jCyb8HbcsjzQjL4y7o/K4V6283nBiwl0FNkSvSNn4LV2ud
kiVYWhz3NN40Amwk5vnBgjOjTLaDcN8GCGpUlPy3Rvxx2GdccEpXuHRwqpOO4m4c
y1CbiLy+L95YnWkYCtJOsLJohCG9WW+OwjeF3sOsnosM6cbG1D+/eonAd5g1TinG
ejlZKHrxihgU6cgdfkw0dP6S7ullFHaqV8gEr5sn9hLYeOZsH3HMAf3DA8pJncvu
owLabIizTfXLQvBSrjiho2nlZRIjbzV/0T6fY1pS7mr6wiMGGkjOT/bfEZCO8CMu
7C3wh3gcpb0/AoIP1Gd0+hM80pkKcjkb+OrblkdtdWwhlCsb0YBtnuQ0LW39Q0B+
8kNOpWB+ff6mq17SC2IqPl2obMiWkzn8HHAPsECtikdWKXN2weC6/+jvbOlDPKjY
4Esva0nEwzFI6mfLdbULidaIsbAYS4IKzXwKYbpMVvU0brYv/zMby56yPj/TEHlo
nm0uOiinvrmTM+QEOFjamxleBlCHHcLoCMsds8fwtlXhFoI8bdGIisVtpZjcnI2x
cyKFCPn3RMj8aUs3gdhjIcmfZdzpiwjGwlLEDKYQ60qsATJv5z0jv1nUPxkz1ush
bsigCn3LzekOZFSWZd7d0CVswYQI9Hn8/H3bkDZyf4dyQQ6kPPWqFocJ7BnS0j+4
I/RleaXNEKp7xxWGgxF1lT/Eaj3GUDz4UmEvcnNseP96LTx6sQwIQYxnNXWQOzrT
sez3v7DARP10HoMurvF7/++0LX0WbvimHKZNj0Itc1ejndVdoFKYX626VmsvWL+i
gxmq8jeGqnPvLXXRgnGuksVMfrvrW4vtP2xqNL8xhVlGU0fUFAgdrSfuWhH6l209
anvhfEo1SGvoezBY/HOaWyG4Dt5A2k9TPqXxbFHuC3U/tAAzUHwwKVSgmapJB8o1
Gp+sZ+z+dBl5prKYamjNtwC6lrX3ijCeyJnX8FRIQfIbAsdEuq9ZH7elWHxCQ68n
oEyQ/ZVs7JE5rTd01cE3vt1d6R7qY2H7xBwaWHrTr3RI0N/zMIhSuMIYReH01B84
9G8jgPB40vmLHGF2Se0zDSwu4PZIcCrByaiYcWATKjMifcun5RxmG6ugYBQkBjU8
AE/aspRv54APkxXCGVsW+E/w9R7g5cXDeHBI4Ec51N+dX+brDR0p/SE19+ksr5/g
cCw2rv/URcrbYrFKokxGIohwBKpZCbl61KenYarp5ubZAGHG4SP8kK/t8K+s9DAL
LGsu0gqooxzHiiFlS2PFvM4an3QtMolGSOnAeRP/YXIMLyTmM/Bs0Zw9Hi9w35xR
8UAbG5e5xL/ghOkXmSNuWAiLYctbjHJI5ERSYeERbElrJJjWdGO5caFB8uawVKWM
6leXdluelYQdTibV3Khrx2YqrNBP55NVXctEfHekG19SqTzSWIif3py+JbVTQF31
OK9MsGDvuCMUZH6RSGZrEOrepKg3c04DxoVaBamdz7mj
-----END ENCRYPTED PRIVATE KEY-----
`)

// nolint: gochecknoglobals
// converted with openssl pkcs8 -topk8 -in key.pem -out pkcs8.pem.
var pemPKCS8RSAPrivateKey = []byte(`
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/Fzdkc01Vp8gm
9hF0hn4MNXSoOibXmT3ukvNyCc2NG0D8Iqtt3gzqoxRwqnpP32sS9ENZGUEQTWxM
Rrc60De1b7falEw7NQGhRovM+1cDFgnPMrGXIh5EsArynG05zA/Sz0VBs2d2ZXTx
LRq3kRknNguo33JG4L7Yi37l+85TIitw0ay4UHnYwijL0lhaMjDaB2qNZdVGpXlK
9ZPh+1WO3jcu3+yMGtOJmsNJLoemBtjDQJQGxfQsp50tgRHdJF9IrLsT+8CE6EAQ
g2mlqSMVM8C1QDFMjilKe9PF7j70tNypVDhSJ5BwMEV2pouFbuSnpekh2HJbKXPN
V6k8G0xPAgMBAAECggEAK01UhRPHy4g4x/Ns4y3y9EtMwy5iTOrx6NUuC4KDLN2n
LTuiA0SVQrpv0FQhYWYsemAVvuQFJW+WAfboYJB8f0XwsLx4RdZuJyC4X1v5TL66
vFQtgCUAHOqToISoD7fZQhksBYZlBKRbCqgA7OYZgBQ0MjFoUP1u4d1ChVU5XQb1
im7Yvt9p1q2OYBtax3lUjzzwNymzfOC4xBZFKTnPzJx5sPUXRXp2C6RODpJao4td
Mzcj5dXNt0cF9eE0nkon4NEJbnc6WX4XxM2aI84wyRaPpa9AklK35NbKYSltWJNv
0A55n7m0l9sWSvVA/XjM7vxpO5Awk27i9rViLdUsYQKBgQDyuZ+w1iWVv9r2Fdo1
19TKeOiWwLn3KJEzIz7pmrpTE0ZjXk7S6hNZ6/KOlxdzikCEQTe1BrjdMAtc4lbe
5ia0Xj0eVsHSS+P1oVMz8k6UUPdjUNU8+kJCuMpAUKMok21hGm4npTSyR/Sp2iAT
M/JXWF+D5XRTFixojUbGg67L8QKBgQDJiqm/71WlXfOKHN3vZt5WvBxWVyCpEQbI
bNqnUnWEEeuHh5Fsd+vv5ohoOMwXDtQ6byunvGXE7td+Yt00v79Qtdg5iyxeFZFp
tKaQ7wr6NJ7z8Z15Z8UYuMcEJKP5eNR29uPUaI9vIqum0LZSwvwE7Vcub+QB+LhT
rHOtjhTcPwKBgCcyEHaG7kTTWXF5r+YX91XG1pBZiO4/j8r5OxSQFtyJdUlglkv6
3qsbreyWu4O95JM20N8buciGFJ+oMS0Hb2KbATWf/uaNuL8WkRAHZecPeBOCnxyc
sQyDOK3QF7jarcQLd5RRWkQb2IeBIMLZFZ5DOBFdgT5Vi1BK2A4Af76RAoGBAMh9
a45nHXErPDl5rAIa+DWaXio59GCbcn7xYrau3f6rAP3LDAy2Y3w8fhgH4GdTtiYH
L4tmbGrzGmY9HUb7NOuqalYcL9/MXuKj9ksZsXbj3/hWtEvwwe5s6nYhqQlkfR93
TX+hIIbzG4UP/T/pfmG8ZUzpvA2GCoAaftz5CaFrAoGAJQbF/nNii/pkRW6nTo7+
GXADAyyrW/DYo+XBgxyMAoOPqsjPyYBmZP5jG3LfmCVZHWXyw83SsP35B0Ri4tjc
6/bdJXEec0rLWkZImNOKcGR+M0QE518NStWBrVszDTi1XD/o70QQo0ZpCxLoHR/O
r31pyBUcAO9GOL56rDXzHQk=
-----END PRIVATE KEY-----
`)

func findKeyType(entries []*keystore.Entry, alg string) *keystore.Entry {
	for _, entry := range entries {
		if entry.Alg == alg {
			return entry
		}
	}

	return nil
}

func TestCreateKeyStoreFromPEMFile(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc                 string
		password           string
		keyStoreFile       func(t *testing.T) string
		removeKeyStoreFile func(t *testing.T, file string)
		assert             func(t *testing.T, ks keystore.KeyStore, err error)
	}{
		{
			uc: "file does not exist",
			keyStoreFile: func(t *testing.T) string {
				t.Helper()

				return "foobar.pem"
			},
			removeKeyStoreFile: func(t *testing.T, _ string) { t.Helper() },
			assert: func(t *testing.T, _ keystore.KeyStore, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "no such file")
			},
		},
		{
			uc: "path is a directory",
			keyStoreFile: func(t *testing.T) string {
				t.Helper()

				dir, err := os.MkdirTemp("", "test_dir.*")
				require.NoError(t, err)

				return dir
			},
			removeKeyStoreFile: func(t *testing.T, file string) {
				t.Helper()

				os.Remove(file)
			},
			assert: func(t *testing.T, _ keystore.KeyStore, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "not a file")
			},
		},
		{
			uc: "file not readable",
			keyStoreFile: func(t *testing.T) string {
				t.Helper()

				file, err := os.CreateTemp("", "test_ks.*")
				require.NoError(t, err)

				err = file.Chmod(0o200)
				require.NoError(t, err)

				return file.Name()
			},
			removeKeyStoreFile: func(t *testing.T, file string) {
				t.Helper()

				os.Remove(file)
			},
			assert: func(t *testing.T, _ keystore.KeyStore, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to read")
			},
		},
		{
			uc:       "file contains three keys",
			password: "password",
			keyStoreFile: func(t *testing.T) string {
				t.Helper()

				file, err := os.CreateTemp("", "test_ks.*")
				require.NoError(t, err)

				buf := bytes.NewBuffer(pemPKCS8ECEncryptedPrivateKey)
				_, err = buf.Write(pemPKCS8RSAPrivateKey)
				require.NoError(t, err)

				err = os.WriteFile(file.Name(), buf.Bytes(), 0o600)
				require.NoError(t, err)

				return file.Name()
			},
			removeKeyStoreFile: func(t *testing.T, file string) {
				t.Helper()

				os.Remove(file)
			},
			assert: func(t *testing.T, ks keystore.KeyStore, err error) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, ks)

				assert.Len(t, ks.Entries(), 2)

				ecdsaKeyEntry := findKeyType(ks.Entries(), "ECDSA")
				assert.NotNil(t, ecdsaKeyEntry)
				assert.NotEmpty(t, ecdsaKeyEntry.KeyID)
				assert.NotNil(t, ecdsaKeyEntry.PrivateKey)
				assert.Equal(t, 256, ecdsaKeyEntry.KeySize)
				assert.Nil(t, ecdsaKeyEntry.CertChain)

				rsaKeyEntry := findKeyType(ks.Entries(), "RSA")
				assert.NotNil(t, rsaKeyEntry)
				assert.NotEmpty(t, rsaKeyEntry.KeyID)
				assert.NotNil(t, rsaKeyEntry.PrivateKey)
				assert.Equal(t, 2048, rsaKeyEntry.KeySize)
				assert.Nil(t, rsaKeyEntry.CertChain)

				assert.NotEqual(t, ecdsaKeyEntry.KeyID, rsaKeyEntry.KeyID)
			},
		},
		{
			uc:       "file contains same EC key but in different formats",
			password: "password",
			keyStoreFile: func(t *testing.T) string {
				t.Helper()

				file, err := os.CreateTemp("", "test_ks.*")
				require.NoError(t, err)

				buf := bytes.NewBuffer(pemPKCS1ECPrivateKey)
				_, err = buf.Write(pemPKCS8ECEncryptedPrivateKey)
				require.NoError(t, err)
				_, err = buf.Write(pemPKCS8ECPrivateKey)
				require.NoError(t, err)

				err = os.WriteFile(file.Name(), buf.Bytes(), 0o600)
				require.NoError(t, err)

				return file.Name()
			},
			removeKeyStoreFile: func(t *testing.T, file string) {
				t.Helper()

				os.Remove(file)
			},
			assert: func(t *testing.T, _ keystore.KeyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "duplicate entry")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			file := tc.keyStoreFile(t)

			defer tc.removeKeyStoreFile(t, file)

			// WHEN
			ks, err := keystore.NewKeyStoreFromPEMFile(file, tc.password)

			// THEN
			tc.assert(t, ks, err)
		})
	}
}

func TestCreateKeyStoreFromPEMBytes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		password    string
		pemContents func(t *testing.T) []byte
		assert      func(t *testing.T, ks keystore.KeyStore, err error)
	}{
		{
			uc:       "pem contains same RSA keys but just formatted differently",
			password: "password",
			pemContents: func(t *testing.T) []byte {
				t.Helper()

				buf := bytes.NewBuffer(pemPKCS1RSAPrivateKey)
				_, err := buf.Write(pemPKCS8RSAEncryptedPrivateKey)
				require.NoError(t, err)
				_, err = buf.Write(pemPKCS8RSAPrivateKey)
				require.NoError(t, err)

				return buf.Bytes()
			},
			assert: func(t *testing.T, _ keystore.KeyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "duplicate entry")
			},
		},
		{
			uc: "pem contains unsupported entries",
			pemContents: func(t *testing.T) []byte {
				t.Helper()

				return []byte(`
-----BEGIN FOOBAR KEY-----
MHcCAQEEIAcCM9VY6RRiUlz3UoywbT9yN9UlWEEWKIPqiA2D86pCoAoGCCqGSM49
AwEHoUQDQgAEPEmirqVF2KoNguFuh4GGyShM3OIZt/yD6WESlOvAJhJX6HZyOgFu
xijD/4gPFRBfs2GsfVZzSL9kH7HH0chB9w==
-----END FOOBAR KEY-----
`)
			},
			assert: func(t *testing.T, _ keystore.KeyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "unsupported entry")
			},
		},
		{
			uc: "key decoding error",
			pemContents: func(t *testing.T) []byte {
				t.Helper()

				return []byte(`
-----BEGIN RSA PRIVATE KEY-----
MHcCAQEEIAcCM9VY6RRiUlz3UoywbT9yN9UlWEEWKIPqiA2D86pCoAoGCCqGSM49
AwEHoUQDQgAEPEmirqVF2KoNguFuh4GGyShM3OIZt/yD6WESlOvAJhJX6HZyOgFu
xijD/4gPFRBfs2GsfVZzSL9kH7HH0chB9w==
-----END RSA PRIVATE KEY-----
`)
			},
			assert: func(t *testing.T, _ keystore.KeyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to parse")
			},
		},
		{
			uc: "pem contains a key with X-Key-ID specified",
			pemContents: func(t *testing.T) []byte {
				t.Helper()

				privKey1, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				pemBytes, err := pemx.BuildPEM(
					pemx.WithECDSAPrivateKey(privKey1, pemx.WithHeader("X-Key-ID", "bar")),
				)
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, ks keystore.KeyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ks)

				assert.Len(t, ks.Entries(), 1)

				entry1 := ks.Entries()[0]
				assert.NotNil(t, entry1)
				assert.NotNil(t, entry1.PrivateKey)
				assert.Equal(t, 384, entry1.KeySize)
				assert.Nil(t, entry1.CertChain)
				assert.Equal(t, "bar", entry1.KeyID)
			},
		},
		{
			uc: "pem contains key with cert without SubjectKeyID and without X-Key-ID specified",
			pemContents: func(t *testing.T) []byte {
				t.Helper()

				ca, err := testsupport.NewRootCA("Test CA", time.Hour*24)
				require.NoError(t, err)

				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				cert, err := ca.IssueCertificate(
					testsupport.WithSubject(pkix.Name{
						CommonName:   "Test EE",
						Organization: []string{"Test"},
						Country:      []string{"EU"},
					}),
					testsupport.WithValidity(time.Now(), time.Hour*1),
					testsupport.WithSubjectPubKey(&privKey.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
				require.NoError(t, err)

				pemBytes, err := pemx.BuildPEM(
					pemx.WithECDSAPrivateKey(privKey),
					pemx.WithX509Certificate(cert),
					pemx.WithX509Certificate(ca.Certificate),
				)
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, ks keystore.KeyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ks)

				assert.Len(t, ks.Entries(), 1)

				entry := ks.Entries()[0]
				assert.NotNil(t, entry)
				assert.NotNil(t, entry.PrivateKey)
				assert.Equal(t, 384, entry.KeySize)
				assert.Len(t, entry.CertChain, 2)
				kid, err := pkix2.SubjectKeyID(entry.PrivateKey.Public())
				require.NoError(t, err)
				assert.Equal(t, hex.EncodeToString(kid), entry.KeyID)
			},
		},
		{
			uc: "pem contains keys with cert with SubjectKeyID and without X-Key-ID specified",
			pemContents: func(t *testing.T) []byte {
				t.Helper()

				ca, err := testsupport.NewRootCA("Test CA", time.Hour*24)
				require.NoError(t, err)

				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				cert, err := ca.IssueCertificate(
					testsupport.WithSubject(pkix.Name{
						CommonName:   "Test EE 1",
						Organization: []string{"Test"},
						Country:      []string{"EU"},
					}),
					testsupport.WithValidity(time.Now(), time.Hour*1),
					testsupport.WithSubjectKeyID([]byte("bar")),
					testsupport.WithSubjectPubKey(&privKey.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
				require.NoError(t, err)

				pemBytes, err := pemx.BuildPEM(
					pemx.WithECDSAPrivateKey(privKey),
					pemx.WithX509Certificate(cert),
					pemx.WithX509Certificate(ca.Certificate),
				)
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, ks keystore.KeyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ks)

				assert.Len(t, ks.Entries(), 1)

				entry := ks.Entries()[0]
				assert.NotNil(t, entry)
				assert.NotNil(t, entry.PrivateKey)
				assert.Equal(t, 384, entry.KeySize)
				assert.Len(t, entry.CertChain, 2)
				assert.Equal(t, hex.EncodeToString(entry.CertChain[0].SubjectKeyId), entry.KeyID)
			},
		},
		{
			uc: "pem contains keys with cert with SubjectKeyID and with X-Key-ID specified",
			pemContents: func(t *testing.T) []byte {
				t.Helper()

				ca, err := testsupport.NewRootCA("Test CA", time.Hour*24)
				require.NoError(t, err)

				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				cert, err := ca.IssueCertificate(
					testsupport.WithSubject(pkix.Name{
						CommonName:   "Test EE 1",
						Organization: []string{"Test"},
						Country:      []string{"EU"},
					}),
					testsupport.WithValidity(time.Now(), time.Hour*1),
					testsupport.WithSubjectKeyID([]byte("bar")),
					testsupport.WithSubjectPubKey(&privKey.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
				require.NoError(t, err)

				pemBytes, err := pemx.BuildPEM(
					pemx.WithECDSAPrivateKey(privKey, pemx.WithHeader("X-Key-ID", "foo")),
					pemx.WithX509Certificate(cert),
					pemx.WithX509Certificate(ca.Certificate),
				)
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, ks keystore.KeyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ks)

				assert.Len(t, ks.Entries(), 1)

				entry := ks.Entries()[0]
				assert.NotNil(t, entry)
				assert.NotNil(t, entry.PrivateKey)
				assert.Equal(t, 384, entry.KeySize)
				assert.Len(t, entry.CertChain, 2)
				assert.Equal(t, "foo", entry.KeyID)
			},
		},
		{
			uc: "duplicate key id entry",
			pemContents: func(t *testing.T) []byte {
				t.Helper()

				privKey1, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				privKey2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				pemBytes, err := pemx.BuildPEM(
					pemx.WithECDSAPrivateKey(privKey1, pemx.WithHeader("X-Key-ID", "foo")),
					pemx.WithECDSAPrivateKey(privKey2, pemx.WithHeader("X-Key-ID", "foo")),
				)
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, _ keystore.KeyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "duplicate entry for key_id=foo")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			file := tc.pemContents(t)

			// WHEN
			ks, err := keystore.NewKeyStoreFromPEMBytes(file, tc.password)

			// THEN
			tc.assert(t, ks, err)
		})
	}
}

type testSigner struct{}

func (s testSigner) Public() crypto.PublicKey                                  { return nil }
func (s testSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }

func TestCreateKeyStoreFromKey(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		signer func(t *testing.T) crypto.Signer
		assert func(t *testing.T, ks keystore.KeyStore, err error)
	}{
		{
			uc: "from unsupported key type",
			signer: func(t *testing.T) crypto.Signer {
				t.Helper()

				return testSigner{}
			},
			assert: func(t *testing.T, _ keystore.KeyStore, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported key type")
			},
		},
		{
			uc: "from rsa private key",
			signer: func(t *testing.T) crypto.Signer {
				t.Helper()

				privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				return privateKey
			},
			assert: func(t *testing.T, ks keystore.KeyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ks)

				assert.Len(t, ks.Entries(), 1)

				rsaKeyEntry := findKeyType(ks.Entries(), "RSA")
				assert.NotNil(t, rsaKeyEntry)
				assert.NotEmpty(t, rsaKeyEntry.KeyID)
				assert.NotNil(t, rsaKeyEntry.PrivateKey)
				assert.Equal(t, 2048, rsaKeyEntry.KeySize)
				assert.Nil(t, rsaKeyEntry.CertChain)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			key := tc.signer(t)

			// WHEN
			ks, err := keystore.NewKeyStoreFromKey(key)

			// THEN
			tc.assert(t, ks, err)
		})
	}
}

func TestKeyStoreGetKey(t *testing.T) {
	t.Parallel()

	// GIVEN
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ks, err := keystore.NewKeyStoreFromKey(privateKey)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc     string
		keyID  func(t *testing.T, ks keystore.KeyStore) string
		assert func(t *testing.T, entry *keystore.Entry, err error)
	}{
		{
			uc: "not existing key entry",
			keyID: func(t *testing.T, _ keystore.KeyStore) string {
				t.Helper()

				return "foo"
			},
			assert: func(t *testing.T, _ *keystore.Entry, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, keystore.ErrNoSuchKey)
			},
		},
		{
			uc: "existing key entry",
			keyID: func(t *testing.T, ks keystore.KeyStore) string {
				t.Helper()

				entry := ks.Entries()[0]

				return entry.KeyID
			},
			assert: func(t *testing.T, entry *keystore.Entry, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, entry)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			keyID := tc.keyID(t, ks)

			// WHEN
			entry, err := ks.GetKey(keyID)

			// THEN
			tc.assert(t, entry, err)
		})
	}
}
