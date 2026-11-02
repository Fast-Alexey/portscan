package portscan_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Fast-Alexey/portscan"
)

func TestScanner_OpenAndClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	openPort := ln.Addr().(*net.TCPAddr).Port
	closedPort := openPort + 1000

	s, err := portscan.New(
		portscan.WithConcurrency(2),
		portscan.WithConnectTimeout(200*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	results, err := s.Scan(context.Background(), []string{"127.0.0.1"}, portscan.Ports(openPort, closedPort))
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	foundOpen := false
	for res := range results {
		if res.Port == uint16(openPort) {
			if res.State != portscan.StateOpen {
				t.Errorf("expected open port %d, got %s", openPort, res.State)
			}
			foundOpen = true
		}
	}

	if !foundOpen {
		t.Error("open port result was not received")
	}
}

func TestScanner_ContextCancel(t *testing.T) {
	s, err := portscan.New(portscan.WithConcurrency(5))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := s.Scan(ctx, []string{"127.0.0.1"}, portscan.Range(1, 100))

	if err != nil {
		t.Fatal(err)
	}

	for res := range results {
		if res.State != portscan.StateCanceled {
			t.Errorf("expected StateCanceled, got %s", res.State)
		}
	}
}

func TestScanner_SlowConsumer(t *testing.T) {
	s, err := portscan.New(
		portscan.WithConcurrency(10),
		portscan.WithConnectTimeout(50*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	results, err := s.Scan(ctx, []string{"127.0.0.1"}, portscan.Range(1, 500))
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for range results {
		count++
		if count >= 3 {
			cancel()
			break
		}
	}
}

func TestScanner_Reusability(t *testing.T) {
	s, err := portscan.New(portscan.WithConcurrency(5))
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := s.Scan(context.Background(), []string{"127.0.0.1"}, portscan.Ports(80))
			if err != nil {
				t.Errorf("scan error: %v", err)
				return
			}
			for range results {
			}
		}()
	}
	wg.Wait()
}
