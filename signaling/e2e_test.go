package connect

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEndToEnd(t *testing.T) {
	srv := httptest.NewServer(newServer(t.Context(), Config{}))
	defer srv.Close()

	receiverPub, receiverPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverStr := base64.RawURLEncoding.EncodeToString(receiverPub)

	// Receiver opens SSE stream.
	sse := connectSSE(t, srv.URL, receiverPub, receiverPriv)
	defer sse.Body.Close()

	// Read the first data line from SSE in the background.
	got := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(sse.Body)
		for s.Scan() {
			if result, ok := strings.CutPrefix(s.Text(), "data: "); ok {
				got <- result
				return
			}
		}
		if err := s.Err(); err != nil {
			t.Errorf("SSE read error: %v", err)
		}
	}()

	// Sender posts a payload to the receiver.
	resp := postSDP(&http.Client{}, srv.URL, receiverStr, testSDP)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST status: got %d, want %d", resp.StatusCode, http.StatusAccepted)
	}

	// Verify the payload arrived intact.
	if data := <-got; data != string(testSDP) {
		t.Fatalf("SSE data: got %q, want %q", data, string(testSDP))
	}
}
