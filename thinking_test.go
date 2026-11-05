package main

import "testing"

// Field 11 (thinking text) must ride the wire even when the upstream issued no
// signature — that is the verified Devin CLI shape for unsigned-reasoning
// models like swe-2-flash. 12/18 attach only when a signature exists.
func fieldsOf(m chatMsg) map[int][]protoField {
	out := map[int][]protoField{}
	fs, err := iterFields(encodeChatMessage(m))
	if err != nil {
		panic(err)
	}
	for _, f := range fs {
		out[f.num] = append(out[f.num], f)
	}
	return out
}

func TestEncodeUnsignedThinking(t *testing.T) {
	f := fieldsOf(chatMsg{source: 2, text: "answer", thinking: &SignedThinking{Text: "unsigned summary"}})
	if got := string(f[11][0].b); got != "unsigned summary" {
		t.Fatalf("field 11 = %q", got)
	}
	if len(f[12]) != 0 || len(f[18]) != 0 {
		t.Fatal("unsigned thinking must not emit signature fields 12/18")
	}
}

func TestEncodeSignedThinking(t *testing.T) {
	f := fieldsOf(chatMsg{source: 2, text: "answer", thinking: &SignedThinking{
		Text: "summary", Signature: "sealed.v1.x", SigType: "sealed", Redacted: true,
	}})
	if got := string(f[11][0].b); got != "summary" {
		t.Fatalf("field 11 = %q", got)
	}
	if got := string(f[12][0].b); got != "sealed.v1.x" {
		t.Fatalf("field 12 = %q", got)
	}
	if f[13][0].v != 1 || string(f[18][0].b) != "sealed" {
		t.Fatal("redacted flag / signature_type missing")
	}
}

func TestSigStoreUnsignedRoundTrip(t *testing.T) {
	s := newSigStore(8, 0)
	key := digestOf("reasoning", "unsigned text")
	s.put(key, &SignedThinking{Text: "unsigned text", Selector: "swe-2-flash-medium"})
	// Unsigned blobs replay regardless of selector — nothing to verify.
	got := s.get(key, "swe-2-high")
	if got == nil || got.Text != "unsigned text" {
		t.Fatal("unsigned blob did not round-trip")
	}
}

func TestSigStoreSignedSelectorGuard(t *testing.T) {
	s := newSigStore(8, 0)
	key := digestOf("reasoning", "signed text")
	s.put(key, &SignedThinking{Text: "signed text", Signature: "sealed.v1.x", Selector: "swe-2-medium"})
	if s.get(key, "swe-2-flash-medium") != nil {
		t.Fatal("signed blob must not replay to a different selector")
	}
	if s.get(key, "swe-2-medium") == nil {
		t.Fatal("signed blob must replay to its own selector")
	}
}

// A turn whose thinking arrived without a signature event must still land in
// the store (previously it was dropped entirely).
func TestCommitStoresUnsignedThinking(t *testing.T) {
	store = newSigStore(64, 0)
	a := newAssembled()
	a.feed(chatEvent{kind: "reasoning", text: "unsigned fragment"}, nil)
	a.text.WriteString("visible answer")
	a.commit("swe-2-flash-medium")
	got := store.get(digestOf("reasoning", "unsigned fragment"), "swe-2-flash-medium")
	if got == nil || got.Text != "unsigned fragment" {
		t.Fatal("unsigned thinking was not committed")
	}
	got = store.get(digestOf("assistant", "visible answer", toolCallDigest(nil)), "swe-2-flash-medium")
	if got == nil || got.Text != "unsigned fragment" {
		t.Fatal("unsigned thinking was not indexed under the assistant digest")
	}
}
