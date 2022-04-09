package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nolint
var pemContents = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEOoptIY9tD4tkMnK1tUWCOAYkskw+Gs8VC54GvrDGSaoAoGCCqGSM49
AwEHoUQDQgAEmK78mrIE2dddKSTmANA/coTQpabnpdPmVgIGAGuO7SA1BSrySZi1
aAsyCuJI3sZ0/++l8UZRyKNtA7J0e4X+yw==
-----END EC PRIVATE KEY-----
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAgLTDlvF7q25AICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEFeNKfRWbGTzNAVgwS4RRCYEgZDD
kEiCnT+7PrO3Bjj9+2GbrWLAQlhhDwLbLnpFJITaLhyxlyvkkrqi/9usMAwAqjkd
P1gquO94eELxoUbqJbimklcYZgwVr9yO7qVtzYHG1BeBf7cnkxK0l0544yXVp5ul
Cx3Ljo2vI48aZm3HiebE06fc+/HwRSKT+nuvmS94km1FmEnF9t5ya2yW1XV+6hc=
-----END ENCRYPTED PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD2R5MppaQsa99m
Hnnq8m7ldHsTYtQMK8/ze3Ms0PYDCgCPX8bL+N/XNvsaYuNvY6RtlfcKCS8rTNdX
dqgRlDbfH7QM83WevSIT2e5OpL4Hn0vLWSCwlaNveYZ0Ubx5WOT0Tgmd6W7UkFm/
AOogrBTOByALquAK/9HOgTsJq1TLvYbIa45w9D1MXe43mLBpdWSoQZpD+OhbS4O4
3MndbEfJ5cED3+gEx1cOgkN0PiadkIsggarnTtyECfPnK7a/YCSvVzw5ovpcAMOA
wGejsqxXTsZ8pnxnF6kHlvtfQyOsstj61fJz5zu5P//+A/R7M7tIRzLTkfPuPoJK
r4QMnhutAgMBAAECggEBAMCMr1NFbTlJ0az+sOVvTCLb0goTH6SwcHJ2F1N3wJAZ
ttxhzoTU/PU/yE0V+amyJvGC6VWQXq+k8Uwxui+cSNZj7BqgElrclpMctUQJa4V8
Fv9SnMtTAyf5xJSW/xuE0+TqSnyK8JsCjRhXt7V5tP5r9bMJkwcmgbvJsAXcTXzI
Fb/2LFDHXTmK0+SCdENT52o///s0Xb8xcRUtaNGaw258WwjMnQjJDlegAqei+IAK
5A+BBmwa0Fxp32XZl3cyMFiEYm+oQcLFZ4fDSW+iIIq7lbNwiLQpuDdbeHSLaNq5
vPpmt9Cm40AA2o6QY6WEJLeaaebFNqcVaR8WpgznDIUCgYEA/NqjeIVAjPefU7Qo
kgyBpq/tC2fniYE7IJ+l3++nwkSU5IISXJdohyJOX23M8EvG6IBCiuI1LrARPWkS
h64BzD0AwUWhD4DL8DTl/3wxD+Thdt0cBlAvKpf7jAvy/77KOj/NAZpeaQHf00sg
Zb1XGszaCh1QvOH3x4f4h+rnBd8CgYEA+Vf+/g8i8vNkuEi4kIb4IpAJpNoT37Sz
l2aLC3K7xJ8XoJoWD2tw/iJR2LSfFiiulyC0C9/nB7+V/S9jbPybKA4SDsFfYlXK
yiW+O3lH+/CgD2l4i1HgSxHYXAFNGwzoN4IvS6daqzOzUYdVFH7H6p82pyy4DCJY
GvMotmrDl/MCgYEA+VjSo+MkCN+YKv8akwvqPup2JC1O0vaxzDYjaXX4RUdEXSM3
4D8fQUO/bbPlyYGwoU76T+NK9sOB/MFFGK+r7jCqMe3sKlGkyzgfJ5bc+wOGo6Tg
IgmouaQu16hg9Xq8Cj0oeVA1ke/bPY50YGAbKb6hth+6osljg0y+9ancMJkCgYBK
01hnP32acOYR02jnnklKffUW7oa2RFD8pz4kwlqMx71cacEjAXgYG456PMHc8Xpr
SdoeEiQPlDPbleP9adTZ8VcD7I3GQb6oaSksSdoLRguSdHFDRd/MR1+pRI6yBm6N
cdjlmCRCajJuzfD/RIiT5RGOm4Hjyk6sT7ow+9sUdwKBgFLRPGElXQ4zML6ZmJwc
yyrTB02JDbkY3TSK7h/c+dvSn37C8HyyNDZFu1wyVIIfFkR21sX3JPvlfwiUUde9
9fh7jdR0m/vVkEfXqQhj3us96m87XPf4dvwbbP6/JlPOcwIdwsbV1sNbKOO27vT0
APqGqnhC+v2U1uPEk4mJabnl
-----END PRIVATE KEY-----
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQInDBpQxdsnGACAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBDNMuNfjF1giUmbvpwuKjT9BIIE
0K8qUL0JibhZ6+d4+jAcRvTWfqUU9wTHmXhR67LtbrTII7H174VKe8/E34IJuDWh
KPIz3GEv1i3dG8pTSC3pGD23ADtLCs836RvdI72J/malCS0gor13jF0jtCRa6XCh
aFqSyT08TDMi9SSDnfMDRJQly22mH1/fY9AU92+pkG8NesLMUF/WTOTQhf3plGQZ
1WqPa6vhIRjMpSH8T6cXWbF0No9DCqj1EluIKgVBWD8YslOPXV8mfsbykGNpvJSt
HCE3lpivA2PZ+XYXpGStcR89TtRZoWK8FVjKPyzFVlfufwZdzWYArQYE1msadKg2
0d7urJArQXXwGKwf7B41rOaQuv4MDe9M1IfVhQF/cDZGt+aCAzbxYlK/MxDpj/zX
P8E+q+bJoqBOPezmc7V8UD05NFtN0xRdulTyPmQPEcF1zqItSRh2rA4rLX4NxIeb
GQ5WW0djnm1A3bELPDX67VuKm9KU3njjpSp5w/12a0qKc1HifHi8mGmVV2KWx9Fi
OCKPjwNe567P+QqJvRraQS4UXgVHYWy/7iwIX+wh61/ocMcLIApQHn5gtAw+fnSr
j6VIMnrc84DZgBioOLddnrC45lsIK9+aDqIh6ZTj/9XMwSS1eKgGNfeNDFZVmaRz
9ErskkUTsqFdfYkSPSzoucwY9C8uDCvgwebajg7cK9uujrl68izWnnOU7+OPr9B/
zMdpW4GueGWfZAPe9z0qf08le/X3+srklJ2mzxgJHs+TdjOE62pm2ZjGlU+hoFFs
DpJ4u45+fbZQSOAcvVDMUd57I3ZQTRXYH1fXTO/PGf+zTVONUJ35XmYqV7pypw9F
0/k9becMWioomqhCTSy7iII0mEfXO8HDPC0r8Qnf7dwa9FyllXqzWJS5bABcrNPn
0yx5KHZ4gf9GwgeRZzQmiSAoeVUTnwDDEVOvTXl7E4Kcm9BfY6g1pj158t/j+kIV
rQS8U8NOhrgkBRbFeX8jIJVGK7sm5DQXVUjtPTNl2BJjSWb7CXz83MN19/NfeqmB
cn7udbRnh3N4MeIWg4ID24WtG0rr82r5JAAGOkiZj+HWvpTtqoDoAEVhXlNBUz4c
93N89Zjc/4evTcS8tOi2BDZ16bdfdhUQ1Tpt0iep8+JKX8KP6hq9PLQvFo1l4cE3
Nr7qJYz3EQCOCwk1+6GvNMQRRgdCzfPJPtGyds1Gjk+K+avPDs/VZ+NaTO2vWcQX
GP1SOCVY29NIt+qGSj7X249+8XN6PO4CgEadDq0w1IPSZR8+UFbH+2Rr+V7dYQbF
/vnrX31wzqXIWWb32YegKAAYyjqRk0q7VW2CBe1Lk8dRCXdGUlvl3ubSmwidhbZU
DuZF9h8k5as9onc5SM566Wgg114jof/1U6xCD3E813GU9FrVJvew1qwsQ+00IAZ6
fW8lpkdhQH73p2ArgVeMq7W3XxmSz6T+tmlK0n2jepDu0XMkcsiQRLhcyuBEgAlM
BXY20wo8ih/B83jW2WFTiKXsJQFI1Ad+72h6BimSW58r2sqaQONT9WU5QwjC6d9Q
T4MaOBQq12H+JXV3ZKhqOvLQcRt2iWB61wOz1YWf8gCLBXXEyDBI/ef67hiMM0p4
x74uTA0d1Gow/gWK0CVcgnko/J0Wuebldkx68fK0Xjto
-----END ENCRYPTED PRIVATE KEY-----
`)

func findKeyType(entries []*Entry, alg string) *Entry {
	for _, entry := range entries {
		if entry.Alg == alg {
			return entry
		}
	}

	return nil
}

func TestCreateKeyStoreFromPEMFile(t *testing.T) {
	// GIVEN
	file, err := ioutil.TempFile("", "test_ks.*")
	require.NoError(t, err)

	defer os.Remove(file.Name())

	err = ioutil.WriteFile(file.Name(), pemContents, 0o600)
	require.NoError(t, err)

	// WHEN
	ks, err := NewKeyStoreFromPEMFile(file.Name(), "password")

	// THEN
	require.NoError(t, err)

	require.NotNil(t, ks)

	// expecting just two entries as the above ec and rsa key are just formatted differently
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
}

func TestCreateKeyStoreFromPEMBytes(t *testing.T) {
	// WHEN
	ks, err := NewKeyStoreFromPEMBytes(pemContents, "password")

	// THEN
	assert.NoError(t, err)
	assert.NotNil(t, ks)

	// expecting just two entries as the above ec and rsa key are just formatted differently
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
}

func TestCreateKeyStoreFromKey(t *testing.T) {
	// GIVEN
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// WHEN
	ks, err := NewKeyStoreFromKey(privateKey)

	// THEN
	assert.NoError(t, err)
	assert.NotNil(t, ks)

	assert.Len(t, ks.Entries(), 1)

	rsaKeyEntry := findKeyType(ks.Entries(), "RSA")
	assert.NotNil(t, rsaKeyEntry)
	assert.NotEmpty(t, rsaKeyEntry.KeyID)
	assert.NotNil(t, rsaKeyEntry.PrivateKey)
	assert.Equal(t, 2048, rsaKeyEntry.KeySize)
	assert.Nil(t, rsaKeyEntry.CertChain)
}

func TestKeyStoreNoSuchKeyEntry(t *testing.T) {
	// GIVEN
	ks := make(keyStore)

	// WHEN
	entry, err := ks.GetKey("foo")

	// THEN
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoSuchKey)
	assert.Nil(t, entry)
}
