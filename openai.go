package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ---- misc helpers ----

func uuidv4() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	var s [36]byte
	hex.Encode(s[0:4], b[0:2])
	hex.Encode(s[4:8], b[2:4])
	s[8] = '-'
	hex.Encode(s[9:13], b[4:6])
	s[13] = '-'
	hex.Encode(s[14:18], b[6:8])
	s[18] = '-'
	hex.Encode(s[19:23], b[8:10])
	s[23] = '-'
	hex.Encode(s[24:36], b[10:16])
	return string(s[:])
}

func base64StdDecode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// ---- OpenAI request types ----

type chatRequest struct {
	Model        string          `json:"model"`
	Messages     []oaiMessage    `json:"messages"`
	Stream       bool            `json:"stream"`
	Tools        []oaiTool       `json:"tools"`
	StreamOpts   *streamOptions  `json:"stream_options"`
	MaxTokens    int             `json:"max_tokens"`
	MaxCompToks  int             `json:"max_completion_tokens"`
}

type streamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

type oaiTool struct {
	Type     string          `json:"type"`
	Function oaiToolFunction `json:"function"`
}

type oaiToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type oaiMessage struct {
	Role             string          `json:"role"`
	Content          json.RawMessage `json:"content"` // string | [{type,text|image_url}]
	ReasoningContent string          `json:"reasoning_content,omitempty"`
	ToolCalls        []oaiToolCall   `json:"tool_calls,omitempty"`
	ToolCallID       string          `json:"tool_call_id,omitempty"`
	Name             string          `json:"name,omitempty"`
}

type oaiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
	Index int `json:"index,omitempty"` // stream-side
}

// contentBlock flattens OpenAI content into text + inline images.
type contentBlock struct {
	text   string
	images [][2]string // {b64, mime}
}

func flattenContent(raw json.RawMessage) contentBlock {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return contentBlock{text: s}
	}
	var parts []struct {
		Type     string `json:"type"`
		Text     string `json:"text"`
		ImageURL *struct {
			URL string `json:"url"`
		} `json:"image_url"`
	}
	var out contentBlock
	if json.Unmarshal(raw, &parts) != nil {
		return out
	}
	var texts []string
	for _, p := range parts {
		switch p.Type {
		case "text":
			texts = append(texts, p.Text)
		case "image_url", "input_image":
			u := ""
			if p.ImageURL != nil {
				u = p.ImageURL.URL
			}
			if i := strings.Index(u, ";base64,"); i >= 0 && strings.HasPrefix(u, "data:") {
				mime := u[5:i]
				out.images = append(out.images, [2]string{u[i+8:], mime})
			}
		}
	}
	out.text = strings.Join(texts, "\n")
	return out
}

// ---- Devin payload ----

type devinTool struct {
	Name, Description string
	Parameters        json.RawMessage
}

type devinPayload struct {
	system    string
	messages  []chatMsg
	tools     []devinTool
	selector  string
	maxTokens int
}

var modelAliases = map[string]string{
	"swe-2":         "swe-2-medium",
	"swe2":          "swe-2-medium",
	"swe-2.0":       "swe-2-medium",
	"swe-2.0-medium": "swe-2-medium",
	"swe-2.0-high":  "swe-2-high",
	"swe-2.0-max":   "swe-2-max",
}

func resolveSelector(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		if d := os.Getenv("DEVIN_DEFAULT_MODEL"); d != "" {
			return d
		}
		return defaultUpstreamModel
	}
	if a, ok := modelAliases[m]; ok {
		return a
	}
	// Normalize dotted version suffixes ("swe-2.0-high" already aliased; the
	// generic "x.y" → "x-y" covers e.g. "claude-opus-4.8" → "claude-opus-4-8").
	return strings.ReplaceAll(m, ".", "-")
}

// toDevinPayload maps OpenAI messages to Devin history. Signature rehydration:
// for every assistant turn we consult sigStore — first by reasoning text (the
// client echoed reasoning_content), then by assistant text+tool_calls digest.
// A miss simply leaves the turn unsigned (swe family tolerates; signed-required
// families like claude-opus would 400 — surfaced as an upstream error).
func toDevinPayload(req *chatRequest, store *sigStore) *devinPayload {
	selector := resolveSelector(req.Model)
	maxTok := req.MaxCompToks
	if maxTok == 0 {
		maxTok = req.MaxTokens
	}
	p := &devinPayload{selector: selector, maxTokens: maxTok}

	var sysParts []string
	var msgs []chatMsg
	for _, m := range req.Messages {
		switch m.Role {
		case "system", "developer":
			if t := flattenContent(m.Content).text; t != "" {
				sysParts = append(sysParts, t)
			}
			continue
		case "user":
			c := flattenContent(m.Content)
			msgs = append(msgs, chatMsg{source: 1, text: c.text, images: c.images})
		case "assistant":
			c := flattenContent(m.Content)
			am := chatMsg{source: 2, text: c.text}
			for _, tc := range m.ToolCalls {
				am.toolCalls = append(am.toolCalls, chatToolCall{
					ID:   tc.ID,
					Name: tc.Function.Name,
					Args: tc.Function.Arguments,
				})
			}
			// Rehydrate the signed thinking blob. Two keys: the reasoning the
			// client echoed, and the assistant content itself (when the client
			// strips reasoning_content entirely).
			var blob *SignedThinking
			if m.ReasoningContent != "" {
				blob = store.get(digestOf("reasoning", m.ReasoningContent), selector)
			}
			if blob == nil {
				blob = store.get(digestOf("assistant", c.text, toolCallDigest(am.toolCalls)), selector)
			}
			am.thinking = blob
			if c.text == "" && len(am.toolCalls) == 0 && blob == nil {
				continue // drop empty assistant turns (upstream rejects them)
			}
			msgs = append(msgs, am)
		case "tool":
			c := flattenContent(m.Content)
			msgs = append(msgs, chatMsg{
				source:     4,
				text:       firstNonEmpty(c.text, "[tool result]"),
				toolCallID: m.ToolCallID,
			})
		}
	}

	p.system = strings.Join(sysParts, "\n")
	p.messages = mergeSameSource(msgs)
	for _, t := range req.Tools {
		if t.Type != "" && t.Type != "function" {
			continue
		}
		p.tools = append(p.tools, devinTool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			Parameters:  t.Function.Parameters,
		})
	}
	return p
}

func toolCallDigest(calls []chatToolCall) string {
	var b strings.Builder
	for _, c := range calls {
		fmt.Fprintf(&b, "%s\x00%s\x00%s\x00", c.ID, c.Name, c.Args)
	}
	return b.String()
}

func firstNonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// Upstream rejects a run of >=3 consecutive same-source text messages; merge.
func mergeSameSource(in []chatMsg) []chatMsg {
	var out []chatMsg
	for _, m := range in {
		if len(out) > 0 {
			prev := &out[len(out)-1]
			if prev.source == m.source &&
				len(prev.toolCalls) == 0 && len(m.toolCalls) == 0 &&
				prev.thinking == nil && m.thinking == nil &&
				prev.toolCallID == "" && m.toolCallID == "" &&
				len(prev.images) == 0 && len(m.images) == 0 {
				prev.text = strings.TrimSpace(prev.text + "\n\n" + m.text)
				continue
			}
		}
		out = append(out, m)
	}
	return out
}

// Conversation identity for #16 cascade_id / trajectory / session: stable per
// conversation root so the upstream sees one continuous session.
func convKey(req *chatRequest, p *devinPayload) string {
	var root string
	for _, m := range req.Messages {
		if m.Role == "user" {
			root = flattenContent(m.Content).text
			break
		}
	}
	return digestOf(p.selector, p.system, root)
}
