package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
)

// classifyError maps net.DialContext errors to State without parsing strings.
func classifyError(err error, ctx context.Context) (State, error) {
	if err == nil {
		return StateOpen, nil
	}

	if errors.Is(err, context.Canceled) || (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) {
		return StateCanceled, err
	}

	if errors.Is(err, context.DeadlineExceeded) || (ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return StateTimeout, err
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout, err
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			return checkSyscallErrno(sysErr.Err, err)
		}
		var errno syscall.Errno
		if errors.As(opErr.Err, &errno) {
			return checkSyscallErrno(errno, err)
		}
	}

	return StateError, err
}

// checkSyscallErrno inspects low-level syscall errnos to determine port reachability state.
func checkSyscallErrno(sysErr error, origErr error) (State, error) {
	var errno syscall.Errno
	if errors.As(sysErr, &errno) {
		switch errno {
		case syscall.ECONNREFUSED:
			return StateClosed, origErr
		case syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.ENETDOWN:
			return StateUnreachable, origErr
		case syscall.ETIMEDOUT:
			return StateTimeout, origErr
		}
	}
	return StateError, origErr
}
