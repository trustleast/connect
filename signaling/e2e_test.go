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
	srv := httptest.NewServer(newServer(t.Context(), nil))
	defer srv.Close()

	receiverPub, receiverPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverStr := base64.RawURLEncoding.EncodeToString(receiverPub)

	// Receiver opens SSE stream.
	sse := connectSSE(t, srv.URL, receiverPriv)
	defer sse.Body.Close()

	// Skip the first data line (node routing token); read the second (the message).
	got := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(sse.Body)
		tokenSkipped := false
		for s.Scan() {
			result, ok := strings.CutPrefix(s.Text(), "data: ")
			if !ok {
				continue
			}
			if !tokenSkipped {
				tokenSkipped = true
				continue
			}
			got <- result
			return
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
