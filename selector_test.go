package main

import "testing"

func TestSelector(t *testing.T) {
	cases := []struct{ model, effort, want string }{
		{"swe-2", "", "swe-2-medium"},
		{"swe-2", "high", "swe-2-high"},
		{"swe-2", "max", "swe-2-max"},
		{"swe-2", "low", "swe-2-medium"},    // clamp: no low variant
		{"swe-2", "xhigh", "swe-2-max"},     // clamp up
		{"swe-2-high", "", "swe-2-high"},    // explicit suffix
		{"swe-2-high", "low", "swe-2-high"}, // name suffix beats param
		{"swe2", "high", "swe-2-high"},
		{"SWE-2.0", "max", "swe-2-max"},
		{"swe-1-6-fast", "", "swe-1-6-fast"}, // non-effort family passthrough
		{"swe-1-7", "high", "swe-1-7"},       // effort ignored, no variants
		{"", "", "swe-2-medium"},             // default model
	}
	for _, c := range cases {
		if got := resolveSelector(c.model, c.effort); got != c.want {
			t.Errorf("resolveSelector(%q,%q)=%q want %q", c.model, c.effort, got, c.want)
		}
	}
}
