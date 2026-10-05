// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestGenericProxyRoutesAllSuffixesWithoutFallback(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	address := testProxy(t, func(c net.Conn) {
		var request ProxyRequest
		if err := ReadProxyMessage(c, &request); err != nil {
			return
		}
		mu.Lock()
		seen[request.Authority]++
		mu.Unlock()
		_ = WriteProxyMessage(c, ProxyResponse{Version: 1, OK: false, Error: "ROUTE_UNAVAILABLE"})
	})
	registry := NewRegistry()
	direct := adapterTestEndpoint(9761)
	if err := registry.Register("alpha", StaticAdapter{"node.alpha": direct}); err != nil {
		t.Fatal(err)
	}
	if err := registry.SetProxy(address); err != nil {
		t.Fatal(err)
	}
	for _, authority := range []string{"node.alpha", "node.beta", "node.gamma"} {
		if _, err := registry.Resolve(context.Background(), authority); err == nil {
			t.Fatal("proxy failure fell back to direct adapter")
		}
	}
	mu.Lock()
	if len(seen) != 3 {
		t.Fatal("proxy selected only one network")
	}
	mu.Unlock()
	if err := registry.SetProxy(""); err != nil {
		t.Fatal(err)
	}
	got, err := registry.Resolve(context.Background(), "node.alpha")
	if err != nil || got != direct {
		t.Fatal("direct adapter requires another application", err)
	}
}

func TestGenericProxyConfigAndConcurrentChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data, _ := json.Marshal(map[string]any{"version": 2, "proxy": map[string]string{"address": "127.0.0.1:41001"}})
	os.WriteFile(path, data, 0600)
	registry, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 30; i++ {
				if err := registry.SetProxy(""); err != nil {
					t.Error(err)
				}
				if _, err := registry.Resolve(ctx, "node.alpha"); !errors.Is(err, context.Canceled) {
					t.Error(err)
				}
				if err := registry.SetProxy("127.0.0.1:41001"); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	workers.Wait()
}
