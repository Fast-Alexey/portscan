package portscan

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestClassifyError(t *testing.T) {
	t.Run("nil error is StateOpen", func(t *testing.T) {
		state, err := classifyError(nil, context.Background())
		if state != StateOpen || err != nil {
			t.Fatalf("expected Open, got %v", state)
		}
	})

	t.Run("context canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		state, _ := classifyError(ctx.Err(), ctx)
		if state != StateCanceled {
			t.Fatalf("expected StateCanceled, got %v", state)
		}
	})

	t.Run("context deadline exceeded", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
		defer cancel()
		state, _ := classifyError(ctx.Err(), ctx)
		if state != StateTimeout {
			t.Fatalf("expected StateTimeout, got %v", state)
		}
	})

	t.Run("syscall ECONNREFUSED", func(t *testing.T) {
		opErr := &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: &os.SyscallError{
				Syscall: "connect",
				Err:     syscall.ECONNREFUSED,
			},
		}
		state, _ := classifyError(opErr, context.Background())
		if state != StateClosed {
			t.Fatalf("expected StateClosed, got %v", state)
		}
	})

	t.Run("syscall EHOSTUNREACH", func(t *testing.T) {
		opErr := &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: syscall.EHOSTUNREACH,
		}
		state, _ := classifyError(opErr, context.Background())
		if state != StateUnreachable {
			t.Fatalf("expected StateUnreachable, got %v", state)
		}
	})
}
