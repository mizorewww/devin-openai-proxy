package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// devin-openai-proxy — minimal OpenAI-compatible reverse proxy for Devin's
// cloud GetChatMessage endpoint (swe-2 family and friends). Single user, no
// deps, streaming-first.
//
// Encrypted CoT: the upstream issues an opaque signature per thinking block
// (response #10/#21). We return the thinking text to the client as
// reasoning_content and stash the signed blob in sigStore keyed by content
// digests; on the next request it is replayed via ChatMessage #11/#12/#13/#18
// — the same replay the official CLI performs — so verified CoT continuity
// survives a stateless OpenAI client.

var (
	cfgAPIKey  string
	cfgAuthKey string
	store      = newSigStore(2048, 7*24*time.Hour)

	convMu  sync.Mutex
	convIDs = map[string]ids{} // convKey -> {session,cascade,trajectory}
)

func convIDBundle(key string) ids {
	convMu.Lock()
	defer convMu.Unlock()
	if v, ok := convIDs[key]; ok {
		return v
	}
	v := ids{session: uuidv4(), cascade: uuidv4(), trajectory: uuidv4()}
	if len(convIDs) > 1024 {
		// cheap FIFO clear — single-user service, a full rebuild is fine
		convIDs = map[string]ids{key: v}
		return v
	}
	convIDs[key] = v
	return v
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[devin-proxy] ")

	key, err := loadAPIKey()
	if err != nil {
		log.Fatalf("startup: %v", err)
	}
	cfgAPIKey = key
	cfgAuthKey = os.Getenv("AUTH_KEY") // empty = open (loopback use)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/v1/models", withAuth(listModels))
	mux.HandleFunc("/v1/chat/completions", withAuth(chatCompletions))

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = "127.0.0.1:8795"
	}
	log.Printf("listening on %s (upstream %s)", addr, host())
	log.Fatal(http.ListenAndServe(addr, mux))
}

func withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfgAuthKey != "" {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if tok != cfgAuthKey {
				writeErr(w, 401, "invalid_request_error", "invalid API key")
				return
			}
		}
		next(w, r)
	}
}

func listModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "invalid_request_error", "method not allowed")
		return
	}
	// Families only — reasoning effort is a request parameter
	// (reasoning_effort), not a separate model, per the OpenAI API shape.
	names := []string{"swe-2", "swe-1-7", "swe-1-7-lightning", "swe-1-6", "swe-1-6-fast", "swe-1-6-slow"}
	out := map[string]any{"object": "list", "data": []any{}}
	for _, n := range names {
		out["data"] = append(out["data"].([]any), map[string]any{
			"id": n, "object": "model", "created": 0, "owned_by": "devin",
		})
	}
	writeJSON(w, 200, out)
}

func chatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "invalid_request_error", "method not allowed")
		return
	}
	var req chatRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<20)).Decode(&req); err != nil {
		writeErr(w, 400, "invalid_request_error", "bad JSON: "+err.Error())
		return
	}
	if len(req.Messages) == 0 {
		writeErr(w, 400, "invalid_request_error", "messages required")
		return
	}
	payload := toDevinPayload(&req, store)
	if len(payload.messages) == 0 {
		writeErr(w, 400, "invalid_request_error", "no usable messages")
		return
	}
	selector := payload.selector
	log.Printf("%s %s -> selector=%s msgs=%d stream=%v", r.Method, r.URL.Path, selector, len(payload.messages), req.Stream)
	bundle := convIDBundle(convKey(&req, payload))

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Minute)
	defer cancel()
	events := make(chan chatEvent, 64)
	errCh := make(chan error, 1)
	go func() { errCh <- streamChat(ctx, cfgAPIKey, payload, bundle, events) }()

	if req.Stream {
		serveStream(w, r, &req, selector, events, errCh)
	} else {
		serveBuffered(w, &req, selector, events, errCh)
	}
}

// ---- response assembly ----

type assembled struct {
	text      strings.Builder
	reasoning strings.Builder
	signed    []SignedThinking // per thinking block, newest last
	curThink  *SignedThinking
	toolCalls []chatToolCall
	callIdx   map[string]int
	activeID  string
	finish    string
	usage     *usageStats
}

func newAssembled() *assembled {
	return &assembled{finish: "stop", callIdx: map[string]int{}}
}

// feed folds one upstream event into the assembled turn. Returns SSE deltas to
// emit (nil for buffered mode where we only care about the final state).
func (a *assembled) feed(ev chatEvent, emit func(kind string, v any)) {
	switch ev.kind {
	case "text":
		a.text.WriteString(ev.text)
		if emit != nil {
			emit("content", ev.text)
		}
	case "reasoning":
		if a.curThink == nil || a.curThink.Signature != "" {
			a.curThink = &SignedThinking{}
		}
		a.curThink.Text += ev.text
		a.reasoning.WriteString(ev.text)
		if emit != nil {
			emit("reasoning_content", ev.text)
		}
	case "redacted":
		if a.curThink == nil {
			a.curThink = &SignedThinking{}
		}
		a.curThink.Redacted = true
	case "signature":
		if a.curThink == nil {
			a.curThink = &SignedThinking{}
		}
		a.curThink.Signature = ev.text
		if ev.sigType != "" {
			a.curThink.SigType = ev.sigType
		}
		a.signed = append(a.signed, *a.curThink)
	case "tool_call":
		c := ev.call
		if c == nil {
			return
		}
		if c.ID != "" && c.Name != "" {
			a.activeID = c.ID
			a.callIdx[c.ID] = len(a.toolCalls)
			a.toolCalls = append(a.toolCalls, chatToolCall{ID: c.ID, Name: c.Name})
			if emit != nil {
				emit("tool_call_start", c)
			}
			if c.Args != "" { // args may arrive piggybacked on the start frame
				a.toolCalls[a.callIdx[c.ID]].Args += c.Args
				if emit != nil {
					emit("tool_call_args", &chatToolCall{ID: c.ID, Args: c.Args})
				}
			}
			return
		}
		// args delta
		idx, ok := a.callIdx[a.activeID]
		if !ok || c.Args == "" {
			return
		}
		a.toolCalls[idx].Args += c.Args
		if emit != nil {
			emit("tool_call_args", &chatToolCall{ID: a.activeID, Args: c.Args})
		}
	case "finish":
		a.finish = ev.finish
	case "usage":
		a.usage = ev.usage
	}
}

// commit stores the turn's signed thinking so a later request can rehydrate it.
func (a *assembled) commit(selector string) {
	for i := range a.signed {
		b := a.signed[i]
		if b.Signature == "" {
			continue
		}
		b.Selector = selector
		b.StoredAt = time.Now()
		if b.Text != "" {
			store.put(digestOf("reasoning", b.Text), &b)
		}
	}
	if len(a.signed) == 0 {
		return
	}
	// Also index the newest signed block under the assistant content digest so
	// clients that drop reasoning_content still get a verified turn.
	last := a.signed[len(a.signed)-1]
	if last.Signature != "" {
		last.Selector = selector
		last.StoredAt = time.Now()
		store.put(digestOf("assistant", a.text.String(), toolCallDigest(a.toolCalls)), &last)
	}
}

func (a *assembled) finishReason() string {
	if len(a.toolCalls) > 0 && a.finish == "stop" {
		return "tool_calls"
	}
	return a.finish
}

func (a *assembled) oaiUsage() map[string]any {
	if a.usage == nil {
		return nil
	}
	u := a.usage
	return map[string]any{
		"prompt_tokens":     u.Prompt,
		"completion_tokens": u.Completion,
		"total_tokens":      u.Prompt + u.Completion + u.Cached + u.CacheCreation,
	}
}

// ---- SSE stream ----

func serveStream(w http.ResponseWriter, r *http.Request, req *chatRequest, selector string, events <-chan chatEvent, errCh <-chan error) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, _ := w.(http.Flusher)

	id := "chatcmpl-" + strings.ReplaceAll(uuidv4(), "-", "")[:29]
	created := time.Now().Unix()
	model := req.Model

	send := func(v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}
	chunk := func(delta map[string]any, finish any) {
		send(map[string]any{
			"id": id, "object": "chat.completion.chunk", "created": created, "model": model,
			"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
		})
	}

	chunk(map[string]any{"role": "assistant", "content": ""}, nil)

	asm := newAssembled()
	emit := func(kind string, v any) {
		switch kind {
		case "content":
			chunk(map[string]any{"content": v}, nil)
		case "reasoning_content":
			chunk(map[string]any{"reasoning_content": v}, nil)
		case "tool_call_start":
			c := v.(*chatToolCall)
			chunk(map[string]any{"tool_calls": []any{map[string]any{
				"index":    len(asm.toolCalls) - 1,
				"id":       c.ID,
				"type":     "function",
				"function": map[string]any{"name": c.Name, "arguments": ""},
			}}}, nil)
		case "tool_call_args":
			c := v.(*chatToolCall)
			idx := 0
			if i, ok := asm.callIdx[c.ID]; ok {
				idx = i
			}
			chunk(map[string]any{"tool_calls": []any{map[string]any{
				"index":    idx,
				"function": map[string]any{"arguments": c.Args},
			}}}, nil)
		}
	}

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	var runErr error

loop:
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				break loop
			}
			asm.feed(ev, emit)
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			runErr = fmt.Errorf("client disconnected")
			break loop
		}
	}
	if err := <-errCh; err != nil {
		runErr = err
	}
	if runErr != nil {
		send(map[string]any{"error": map[string]any{"type": "backend_error", "message": runErr.Error()}})
		chunk(map[string]any{}, "error")
	} else {
		asm.commit(selector)
		chunk(map[string]any{}, asm.finishReason())
		if req.StreamOpts != nil && req.StreamOpts.IncludeUsage {
			if u := asm.oaiUsage(); u != nil {
				send(map[string]any{
					"id": id, "object": "chat.completion.chunk", "created": created,
					"model": model, "choices": []any{}, "usage": u,
				})
			}
		}
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
	flusher.Flush()
}

// ---- buffered (non-stream) ----

func serveBuffered(w http.ResponseWriter, req *chatRequest, selector string, events <-chan chatEvent, errCh <-chan error) {
	asm := newAssembled()
	for ev := range events {
		asm.feed(ev, nil)
	}
	if err := <-errCh; err != nil {
		writeErr(w, 502, "backend_error", err.Error())
		return
	}
	asm.commit(selector)

	msg := map[string]any{"role": "assistant"}
	if asm.text.Len() > 0 || len(asm.toolCalls) == 0 {
		msg["content"] = asm.text.String()
	} else {
		msg["content"] = nil
	}
	if asm.reasoning.Len() > 0 {
		msg["reasoning_content"] = asm.reasoning.String()
	}
	if len(asm.toolCalls) > 0 {
		var calls []map[string]any
		for _, c := range asm.toolCalls {
			calls = append(calls, map[string]any{
				"id": c.ID, "type": "function",
				"function": map[string]any{"name": c.Name, "arguments": c.Args},
			})
		}
		msg["tool_calls"] = calls
	}
	body := map[string]any{
		"id":     "chatcmpl-" + strings.ReplaceAll(uuidv4(), "-", "")[:29],
		"object": "chat.completion", "created": time.Now().Unix(),
		"model": req.Model,
		"choices": []any{map[string]any{
			"index": 0, "message": msg, "finish_reason": asm.finishReason(),
		}},
	}
	if u := asm.oaiUsage(); u != nil {
		body["usage"] = u
	}
	writeJSON(w, 200, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, typ, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{
		"message": msg, "type": typ,
	}})
}
