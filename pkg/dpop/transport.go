package dpop

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Transport is an [http.RoundTripper] that attaches a fresh DPoP proof to
// every request and, when AccessToken is set, the DPoP-bound access token.
//
// It remembers the latest DPoP-Nonce each origin sends and includes it in
// later proofs. When a server rejects a request with "use_dpop_nonce"
// (RFC 9449 §8 and §9), Transport retries once with the new nonce, provided
// the request body can be replayed (its GetBody is set, as it is for
// requests built by [http.NewRequest] from in-memory bodies).
//
// A Transport is safe for concurrent use. The zero value is not usable;
// Signer is required.
type Transport struct {
	// Signer mints the proofs.
	Signer *Signer
	// Base performs the requests; nil means [http.DefaultTransport].
	Base http.RoundTripper
	// AccessToken, when set, returns the DPoP-bound access token for a
	// request. Transport sends it as "Authorization: DPoP <token>" and
	// binds the proof to it with "ath".
	AccessToken func(*http.Request) (string, error)

	mu     sync.Mutex
	nonces map[string]string
}

func origin(r *http.Request) string {
	return strings.ToLower(r.URL.Scheme + "://" + r.URL.Host)
}

func (t *Transport) nonce(key string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.nonces[key]
}

func (t *Transport) remember(key string, resp *http.Response) (string, bool) {
	nonce := resp.Header.Get(NonceHeaderName)
	if nonce == "" {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nonces == nil {
		t.nonces = make(map[string]string)
	}
	changed := t.nonces[key] != nonce
	t.nonces[key] = nonce
	return nonce, changed
}

// RoundTrip implements [http.RoundTripper]. It does not modify req.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Signer == nil {
		return nil, fmt.Errorf("dpop: Transport has no Signer")
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	var token string
	if t.AccessToken != nil {
		var err error
		if token, err = t.AccessToken(req); err != nil {
			return nil, fmt.Errorf("dpop: access token: %w", err)
		}
	}
	key := origin(req)
	sent := t.nonce(key)

	resp, err := t.send(base, req, token, sent)
	if err != nil {
		return nil, err
	}
	nonce, changed := t.remember(key, resp)
	if !changed || !asksForNonce(resp) {
		return resp, nil
	}
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return resp, nil
	}
	// Drain and close the rejected response before retrying.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	return t.send(base, req, token, nonce)
}

func (t *Transport) send(base http.RoundTripper, req *http.Request, token, nonce string) (*http.Response, error) {
	proof, err := t.Signer.ProofForRequest(req, ProofOptions{AccessToken: token, Nonce: nonce})
	if err != nil {
		return nil, err
	}
	out := req.Clone(req.Context())
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("dpop: replay request body: %w", err)
		}
		out.Body = body
	}
	out.Header.Set(HeaderName, proof)
	if token != "" {
		out.Header.Set("Authorization", AuthorizationScheme+" "+token)
	}
	return base.RoundTrip(out)
}

// asksForNonce reports whether resp is a "use_dpop_nonce" error: a 401
// with that error in WWW-Authenticate (resource server, RFC 9449 §9) or a
// 400 whose JSON body names it (authorization server, §8). The body is
// restored for the caller.
func asksForNonce(resp *http.Response) bool {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		for _, value := range resp.Header.Values("WWW-Authenticate") {
			if strings.Contains(value, ErrorUseNonce) {
				return true
			}
		}
	case http.StatusBadRequest:
		if resp.Body == nil {
			return false
		}
		head, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
		return bytes.Contains(head, []byte(ErrorUseNonce))
	}
	return false
}
