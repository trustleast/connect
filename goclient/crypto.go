package connect

import (
	"encoding/binary"
	"time"
)

// Domain separation tags for each signing context.
// Must match across all client implementations.
const (
	domainSSE    = "connect.sse.v1\x00"
	domainOffer  = "connect.offer.v1\x00"
	domainAnswer = "connect.answer.v1\x00"
	domainICE    = "connect.ice.v1\x00"
)

const tsWindowSecs = 30

func concat(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, total)
	n := 0
	for _, p := range parts {
		n += copy(out[n:], p)
	}
	return out
}

// ssePayload returns the signed payload for SSE subscription auth: domain || tsBytes
func ssePayload(tsBytes []byte) []byte {
	return concat([]byte(domainSSE), tsBytes)
}

// offerPayload returns the signed payload for offer messages:
//
//	"connect.offer.v1\0" || challenge[32] || ts[8] || answererPubkey[32] || offerSdp
func offerPayload(challenge, ts, answererPubkey []byte, offerSdp string) []byte {
	return concat([]byte(domainOffer), challenge, ts, answererPubkey, []byte(offerSdp))
}

// answerPayload returns the signed payload for answer messages:
//
//	"connect.answer.v1\0" || challenge[32] || ts[8] || offerSdp || "\x00" || answerSdp
//
// The NUL separator keeps concatenation unambiguous across two variable-length strings.
func answerPayload(challenge, ts []byte, offerSdp, answerSdp string) []byte {
	return concat([]byte(domainAnswer), challenge, ts, []byte(offerSdp), []byte{0}, []byte(answerSdp))
}

// icePayload returns the signed payload for ICE candidate messages:
//
//	"connect.ice.v1\0" || challenge[32] || candidateJson
func icePayload(challenge []byte, candidateJson string) []byte {
	return concat([]byte(domainICE), challenge, []byte(candidateJson))
}

// currentTsBytes returns the current unix time as an 8-byte big-endian uint64.
func currentTsBytes() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(time.Now().Unix()))
	return b
}

// parseTsBytes decodes an 8-byte big-endian uint64 timestamp and returns it
// if within ±tsWindowSecs of the current time, or nil otherwise.
func parseTsBytes(b []byte) []byte {
	if len(b) != 8 {
		return nil
	}
	ts := int64(binary.BigEndian.Uint64(b))
	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > tsWindowSecs {
		return nil
	}
	return b
}
