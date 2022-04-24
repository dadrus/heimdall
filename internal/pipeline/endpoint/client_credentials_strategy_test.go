package endpoint

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApplyClientCredentialsStrategy(t *testing.T) {
	t.Parallel()

	// GIVEN
	clientID := "test-client"
	clientSecret := "test-secret"
	scopes := []string{"foo", "bar"}

	var (
		receivedAuthorization string
		receivedContentType   string
		receivedAcceptType    string
		receivedGrantType     string
		receivedScope         string
		setAccessToken        string
		setExpiresIn          int64
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		receivedAuthorization = r.Header.Get("Authorization")
		receivedContentType = r.Header.Get("Content-Type")
		receivedAcceptType = r.Header.Get("Accept-Type")
		receivedGrantType = r.FormValue("grant_type")
		receivedScope = r.FormValue("scope")

		type response struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int64  `json:"expires_in"`
		}

		blk := make([]byte, 16)
		_, err := rand.Read(blk)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		setAccessToken = base64.StdEncoding.EncodeToString(crypto.SHA256.New().Sum(blk))
		setExpiresIn = 30
		resp := response{
			AccessToken: setAccessToken,
			TokenType:   "Bearer",
			ExpiresIn:   setExpiresIn,
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}
		rawResp, err := json.Marshal(&resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", receivedAcceptType)
		w.Header().Set("Content-Length", strconv.Itoa(len(rawResp)))

		_, err = w.Write(rawResp)
		assert.NoError(t, err)

		return
	}))
	defer srv.Close()

	strategy := ClientCredentialsStrategy{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		TokenURL:     srv.URL,
	}

	req := &http.Request{Header: http.Header{}}

	// WHEN
	err := strategy.Apply(context.Background(), req)

	// THEN
	assert.NoError(t, err)

	val, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(receivedAuthorization, "Basic "))
	assert.NoError(t, err)

	clientIDAndSecret := strings.Split(string(val), ":")
	assert.Equal(t, clientID, clientIDAndSecret[0])
	assert.Equal(t, clientSecret, clientIDAndSecret[1])

	assert.Equal(t, "application/x-www-form-urlencoded", receivedContentType)
	assert.Equal(t, "application/json", receivedAcceptType)
	assert.Equal(t, "client_credentials", receivedGrantType)
	assert.Equal(t, strings.Join(scopes, " "), receivedScope)

	assert.Equal(t, "Bearer "+setAccessToken, req.Header.Get("Authorization"))
}
