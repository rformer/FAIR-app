package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// F-011 T-17 (design §3.3): the runner submits as the integration's
// service account: a client_credentials token by basic authentication
// (never the secret in the URL), then the batch with the token, the
// trigger and the claim's Idempotency-Key.
func TestGatewaySubmitter(t *testing.T) {
	var batchReq *http.Request
	var batchBody []byte
	gw := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/oauth/token":
			_ = r.ParseForm()
			id, secret, ok := r.BasicAuth()
			id, _ = url.QueryUnescape(id)
			secret, _ = url.QueryUnescape(secret)
			if !ok || id != "sa-1" || secret != "s3cret+/=" || r.PostForm.Get("grant_type") != "client_credentials" || r.URL.RawQuery != "" ||
				r.PostForm.Has("client_secret") {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error": "invalid_client"}`)
				return
			}
			fmt.Fprint(w, `{"access_token": "at-1", "token_type": "Bearer", "expires_in": 600}`)
		case "/api/v1/imports/i-1/batches":
			batchReq = r.Clone(context.Background())
			batchBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"run": {"id": "r-1"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer gw.Close()
	u, _ := url.Parse(gw.URL)
	s := GatewaySubmitter{URL: u, Client: gw.Client()}
	status, body, err := s.Submit(context.Background(), Submission{IntegrationID: "i-1", ServiceAccountID: "sa-1", ClientSecret: "s3cret+/=",
		Trigger: "manual", Key: "connector-k1", Body: []byte(`{"format": "fair.integration.v1", "complete": true, "records": []}`)})
	if err != nil || status != 201 {
		t.Fatalf("%d %s %v", status, body, err)
	}
	var res struct {
		Run struct{ ID string } `json:"run"`
	}
	if json.Unmarshal(body, &res) != nil || res.Run.ID != "r-1" {
		t.Errorf("body %s", body)
	}
	if batchReq.Header.Get("Authorization") != "Bearer at-1" || batchReq.Header.Get("Idempotency-Key") != "connector-k1" ||
		batchReq.URL.Query().Get("trigger") != "manual" || !strings.Contains(string(batchBody), `"complete": true`) {
		t.Errorf("batch request %s %v", batchReq.URL, batchReq.Header)
	}
	if _, _, err := s.Submit(context.Background(), Submission{IntegrationID: "i-1", ServiceAccountID: "sa-1", ClientSecret: "wrong"}); err == nil ||
		!strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("a refused token: %v", err)
	}
}
