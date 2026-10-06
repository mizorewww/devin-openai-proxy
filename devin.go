package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Upstream wire — byte-for-byte the same shape as the verified pi-devin
// implementation (docs/protocol-audit-2026-09-29):
//
//   POST https://server.codeium.com/exa.api_server_pb.ApiServerService/GetChatMessage
//   Content-Type: application/connect+proto, Connect-Protocol-Version: 1,
//   Connect-Content-Encoding: gzip, Connect-Accept-Encoding: gzip
//
// ChatMessage history carries the signed-thinking quartet #11 text /
// #12 signature / #13 redacted / #18 signature_type — that is how the upstream
// verifies and continues an encrypted CoT across turns.

const (
	defaultHost          = "https://server.codeium.com"
	clientIDE            = "devin-desktop" // "windsurf" is gated for Devin-Local models
	clientVersion        = "3.10.27"
	defaultMaxOutputTok  = 128000
	defaultUpstreamModel = "swe-2-medium"
)

func host() string {
	if h := strings.TrimRight(os.Getenv("DEVIN_HOST"), "/"); h != "" {
		return h
	}
	return defaultHost
}

func osName() string {
	switch runtime.GOOS {
	case "darwin", "windows":
		return runtime.GOOS
	default:
		return "linux"
	}
}

// ---- credentials ----

// Resolution order: DEVIN_API_KEY env → ~/.local/share/devin/credentials.toml
// (the Devin CLI's own credential store: windsurf_api_key = "...").
func loadAPIKey() (string, error) {
	if k := strings.TrimSpace(os.Getenv("DEVIN_API_KEY")); k != "" {
		return k, nil
	}
	home, _ := os.UserHomeDir()
	raw, err := os.ReadFile(filepath.Join(home, ".local/share/devin/credentials.toml"))
	if err != nil {
		return "", fmt.Errorf("no DEVIN_API_KEY and no devin credentials.toml: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "windsurf_api_key") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		var v string
		if err := json.Unmarshal([]byte(strings.TrimSpace(kv[1])), &v); err == nil && v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("windsurf_api_key not found in credentials.toml")
}

// ---- metadata (request field #1) ----

type ids struct{ session, cascade, trajectory string }

func buildMetadata(apiKey, userJwt string, ids ids) []byte {
	v := clientVersion
	if ov := os.Getenv("DEVIN_CLIENT_VERSION"); ov != "" {
		v = ov
	}
	now := time.Now()
	ts := append(vField(1, uint64(now.Unix())), vField(2, uint64(now.Nanosecond()))...)
	parts := [][]byte{
		sField(1, clientIDE),
		sField(2, v),
		sField(3, apiKey),
		sField(4, "en"),
		sField(5, osName()),
		sField(7, v),
		vField(9, uint64(now.UnixMilli())),
		sField(10, ids.session),
		sField(12, clientIDE),
		mField(16, ts),
		sField(25, uuidv4()),
		sField(26, "Unset"),
		sField(28, clientIDE),
	}
	if userJwt != "" {
		parts = append(parts, sField(21, userJwt))
	}
	return bytes.Join(parts, nil)
}

// ---- user JWT mint + cache ----

var jwtCache struct {
	mu        sync.Mutex
	jwt       string
	expiresAt int64
}

func mintUserJWT(ctx context.Context, apiKey string) (string, int64, error) {
	meta := buildMetadata(apiKey, "", ids{session: uuidv4()})
	body := mField(1, meta)
	req, err := http.NewRequestWithContext(ctx, "POST", host()+"/exa.auth_pb.AuthService/GetUserJwt", bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/proto")
	req.Header.Set("Connect-Protocol-Version", "1")
	resp, err := upstreamHTTP.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, err
	}
	if resp.StatusCode != 200 {
		return "", 0, fmt.Errorf("GetUserJwt HTTP %d: %.240s", resp.StatusCode, buf)
	}
	fields, err := iterFields(buf)
	if err != nil {
		return "", 0, err
	}
	var jwt string
	for _, f := range fields {
		if f.num == 1 && f.wire == 2 && bytes.HasPrefix(f.b, []byte("eyJ")) {
			jwt = string(f.b)
			break
		}
	}
	if jwt == "" {
		return "", 0, fmt.Errorf("GetUserJwt returned no JWT")
	}
	exp := time.Now().Unix() + 600
	if parts := strings.Split(jwt, "."); len(parts) == 3 {
		p := parts[1]
		p += strings.Repeat("=", (4-len(p)%4)%4)
		var claims struct {
			Exp int64 `json:"exp"`
		}
		if dec, err := base64RawURLDecode(p); err == nil && json.Unmarshal(dec, &claims) == nil && claims.Exp > 0 {
			exp = claims.Exp
		}
	}
	return jwt, exp, nil
}

func userJWT(ctx context.Context, apiKey string) (string, error) {
	jwtCache.mu.Lock()
	defer jwtCache.mu.Unlock()
	if jwtCache.jwt != "" && jwtCache.expiresAt > time.Now().Unix()+60 {
		return jwtCache.jwt, nil
	}
	jwt, exp, err := mintUserJWT(ctx, apiKey)
	if err != nil {
		return "", err
	}
	jwtCache.jwt, jwtCache.expiresAt = jwt, exp
	return jwt, nil
}

func base64RawURLDecode(s string) ([]byte, error) {
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	return base64StdDecode(s)
}

// ---- history items ----

type chatToolCall struct {
	ID   string
	Name string
	Args string
}

type chatMsg struct {
	source     int // 1 user / 2 assistant / 4 tool_result
	text       string
	images     [][2]string // {b64, mime}
	toolCalls  []chatToolCall
	toolCallID string
	toolErr    bool
	thinking   *SignedThinking
}

func encodeImage(img [2]string) []byte {
	return bytes.Join([][]byte{sField(1, img[0]), sField(2, img[1])}, nil)
}

func encodeToolCall(tc chatToolCall) []byte {
	return bytes.Join([][]byte{sField(1, tc.ID), sField(2, tc.Name), sField(3, tc.Args)}, nil)
}

func encodeChatMessage(m chatMsg) []byte {
	approx := len(m.text) / 4
	if approx < 1 {
		approx = 1
	}
	parts := [][]byte{
		vField(2, uint64(m.source)),
		sField(3, m.text),
		vField(4, uint64(approx)),
		vField(5, 1),
	}
	if m.toolErr {
		parts = append(parts, vField(9, 1))
	}
	if m.toolCallID != "" {
		parts = append(parts, sField(7, m.toolCallID))
	}
	for _, tc := range m.toolCalls {
		parts = append(parts, mField(6, encodeToolCall(tc)))
	}
	for _, img := range m.images {
		parts = append(parts, mField(10, encodeImage(img)))
	}
	// Signed-CoT quartet — replayed verbatim so the server can verify the trace.
	if m.thinking != nil && m.thinking.Signature != "" {
		parts = append(parts,
			sField(11, m.thinking.Text),
			sField(12, m.thinking.Signature))
		if m.thinking.Redacted {
			parts = append(parts, vField(13, 1))
		}
		if m.thinking.SigType != "" {
			parts = append(parts, sField(18, m.thinking.SigType))
		}
	}
	return bytes.Join(parts, nil)
}

func encodeToolDef(t devinTool) []byte {
	params := t.Parameters
	if len(params) == 0 {
		params = []byte("{}")
	}
	return bytes.Join([][]byte{sField(1, t.Name), sField(2, t.Description), sField(3, string(params))}, nil)
}

func encodeCompletionConfig(maxTokens int) []byte {
	if maxTokens <= 0 || maxTokens > defaultMaxOutputTok {
		maxTokens = defaultMaxOutputTok
	}
	return bytes.Join([][]byte{
		vField(1, 1),                 // num_completions
		vField(2, uint64(maxTokens)), // max_tokens
		vField(3, 400),               // max_newlines
		f64Field(5, 1.0),             // temperature
		vField(7, 40),                // top_k
		f64Field(8, 0.95),            // top_p
	}, nil)
}

func buildRequest(apiKey, jwt string, payload *devinPayload, ids ids) []byte {
	meta := buildMetadata(apiKey, jwt, ids)
	parts := [][]byte{mField(1, meta)}
	if payload.system != "" {
		parts = append(parts, sField(2, payload.system))
	}
	for _, m := range payload.messages {
		parts = append(parts, mField(3, encodeChatMessage(m)))
	}
	traj := bytes.Join([][]byte{sField(1, ids.trajectory), vField(3, 4), vField(4, 14)}, nil)
	parts = append(parts,
		vField(7, 5),
		mField(8, encodeCompletionConfig(payload.maxTokens)),
	)
	for _, t := range payload.tools {
		parts = append(parts, mField(10, encodeToolDef(t)))
	}
	parts = append(parts,
		mField(15, traj),
		sField(16, ids.cascade),
		vField(20, 1),
		sField(21, payload.selector),
	)
	return bytes.Join(parts, nil)
}

// ---- response stream decode ----

type chatEvent struct {
	kind    string // text | reasoning | signature | redacted | tool_call | finish | usage
	text    string
	sigType string
	call    *chatToolCall // tool_call: id/name set on start; argsDelta in .Args
	finish  string
	usage   *usageStats
}

type usageStats struct {
	Prompt, Completion, Cached, CacheCreation int
}

var upstreamHTTP = &http.Client{Timeout: 0} // streaming: no total timeout; ctx rules

// streamChat POSTs GetChatMessage and fans decoded events onto out. The caller
// drains `out` until closed; a terminal error is delivered as a finish event
// with kind="error".
func streamChat(ctx context.Context, apiKey string, payload *devinPayload, ids ids, out chan<- chatEvent) error {
	defer close(out)
	jwt, err := userJWT(ctx, apiKey)
	if err != nil {
		return err
	}
	proto := buildRequest(apiKey, jwt, payload, ids)
	body, err := frameConnectStream(proto, true)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		host()+"/exa.api_server_pb.ApiServerService/GetChatMessage", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/connect+proto")
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set("Connect-Content-Encoding", "gzip")
	req.Header.Set("Connect-Accept-Encoding", "gzip")
	resp, err := upstreamHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("GetChatMessage HTTP %d: %.300s", resp.StatusCode, b)
	}
	return decodeConnectStream(resp.Body, out)
}

func decodeConnectStream(r io.Reader, out chan<- chatEvent) error {
	hdr := make([]byte, 5)
	sawEOS := false
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if err == io.EOF && !sawEOS {
				return fmt.Errorf("stream ended without EOS trailer")
			}
			if err == io.EOF {
				return nil
			}
			return err
		}
		flags := hdr[0]
		n := binary.BigEndian.Uint32(hdr[1:])
		if flags&^0x03 != 0 {
			return fmt.Errorf("unsupported connect frame flags %d", flags)
		}
		if n > maxConnectFrame {
			return fmt.Errorf("frame exceeds %d bytes", maxConnectFrame)
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return err
		}
		if flags&0x01 != 0 {
			zr, err := gzip.NewReader(bytes.NewReader(payload))
			if err != nil {
				return err
			}
			payload, err = io.ReadAll(io.LimitReader(zr, maxConnectFrame))
			zr.Close()
			if err != nil {
				return err
			}
		}
		if flags&0x02 != 0 {
			sawEOS = true
			var trailer struct {
				Error *struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(payload, &trailer) == nil && trailer.Error != nil {
				msg := trailer.Error.Message
				if msg == "" {
					msg = trailer.Error.Code
				}
				return fmt.Errorf("upstream: %s", msg)
			}
			return nil
		}
		if err := decodeChatFrame(payload, out); err != nil {
			return err
		}
	}
}

// GetChatMessageResponse fields (verified):
//
//	3 text delta | 9 thinking delta | 10 signature | 11 thinking_redacted
//	21 signature_type | 6 tool_call {1 id,2 name,3 argsDelta} | 5 finish enum
//	7 ModelUsageStats {2 prompt,3 completion,4 cache_create,5 cached}
//	28 usage metrics (dimension-group form)
func decodeChatFrame(proto []byte, out chan<- chatEvent) error {
	fields, err := iterFields(proto)
	if err != nil {
		return err
	}
	var sig, sigType string
	for _, f := range fields {
		switch {
		case f.num == 3 && f.wire == 2 && len(f.b) > 0:
			out <- chatEvent{kind: "text", text: string(f.b)}
		case f.num == 9 && f.wire == 2 && len(f.b) > 0:
			out <- chatEvent{kind: "reasoning", text: string(f.b)}
		case f.num == 11 && f.wire == 0 && f.v != 0:
			out <- chatEvent{kind: "redacted"}
		case f.num == 10 && f.wire == 2:
			sig = string(f.b)
		case f.num == 21 && f.wire == 2:
			sigType = string(f.b)
		case f.num == 6 && f.wire == 2:
			call, delta, err := decodeToolCallField(f.b)
			if err != nil {
				return err
			}
			if call != nil {
				out <- chatEvent{kind: "tool_call", call: call}
			} else if delta != "" {
				out <- chatEvent{kind: "tool_call", call: &chatToolCall{Args: delta}}
			}
		case f.num == 5 && f.wire == 0:
			out <- chatEvent{kind: "finish", finish: finishName(f.v)}
		case f.num == 7 && f.wire == 2:
			if u := decodeUsageStats(f.b); u != nil {
				out <- chatEvent{kind: "usage", usage: u}
			}
		case f.num == 28 && f.wire == 2:
			if u := decodeUsageDims(f.b); u != nil {
				out <- chatEvent{kind: "usage", usage: u}
			}
		}
	}
	// Signature trails the thinking text in the same frame — emit last so the
	// consumer attaches it to the just-closed block.
	if sig != "" || sigType != "" {
		out <- chatEvent{kind: "signature", text: sig, sigType: sigType}
	}
	return nil
}

func decodeToolCallField(b []byte) (*chatToolCall, string, error) {
	inner, err := iterFields(b)
	if err != nil {
		return nil, "", err
	}
	var id, name, args string
	hasID, hasName := false, false
	for _, f := range inner {
		if f.wire != 2 {
			continue
		}
		switch f.num {
		case 1:
			id, hasID = string(f.b), true
		case 2:
			name, hasName = string(f.b), true
		case 3:
			args = string(f.b)
		}
	}
	if hasID && hasName {
		return &chatToolCall{ID: id, Name: name, Args: args}, "", nil
	}
	return nil, args, nil
}

func decodeUsageStats(b []byte) *usageStats {
	fields, err := iterFields(b)
	if err != nil {
		return nil
	}
	u := &usageStats{}
	seen := false
	for _, f := range fields {
		if f.wire != 0 {
			continue
		}
		seen = true
		switch f.num {
		case 2:
			u.Prompt = int(f.v)
		case 3:
			u.Completion = int(f.v)
		case 4:
			u.CacheCreation = int(f.v)
		case 5:
			u.Cached = int(f.v)
		}
	}
	if !seen {
		return nil
	}
	return u
}

func decodeUsageDims(b []byte) *usageStats {
	fields, err := iterFields(b)
	if err != nil {
		return nil
	}
	u := &usageStats{}
	seen := false
	for _, f := range fields {
		if f.num != 2 || f.wire != 2 {
			continue
		}
		var metric string
		var val float64
		inner, err := iterFields(f.b)
		if err != nil {
			continue
		}
		for _, g := range inner {
			if g.num == 5 && g.wire == 2 {
				metric = string(g.b)
			} else if g.num == 4 && g.wire == 2 {
				dims, err := iterFields(g.b)
				if err != nil {
					continue
				}
				for _, d := range dims {
					if d.num == 2 && d.wire == 5 && len(d.b) == 4 {
						val = float64(math.Float32frombits(binary.LittleEndian.Uint32(d.b)))
					}
				}
			}
		}
		if metric == "" {
			continue
		}
		seen = true
		n := int(val + 0.5)
		switch {
		case metric == "input_tokens":
			u.Prompt = n
		case metric == "output_tokens":
			u.Completion = n
		case strings.Contains(metric, "cached"), strings.Contains(metric, "cache_read"):
			u.Cached = n
		case strings.Contains(metric, "cache_creation"):
			u.CacheCreation = n
		}
	}
	if !seen {
		return nil
	}
	return u
}

func finishName(v uint64) string {
	switch v {
	case 10:
		return "tool_calls"
	case 11:
		return "content_filter"
	case 7, 13:
		return "error"
	case 1, 3, 5, 9:
		return "length"
	default:
		return "stop"
	}
}
