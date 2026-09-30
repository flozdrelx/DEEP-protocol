// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"io"
	"testing"
)

func TestBrowseRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		{"https://example.com/"}, {"deep://name.net/", "--output", "file"},
		{"deep://name.net/", "deep://other.net/"}, {"--unknown"},
	} {
		if err := browseURI(context.Background(), args, io.Discard); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
	if err := run(context.Background(), []string{"browse", "--help"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}
