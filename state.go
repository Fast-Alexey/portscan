package portscan

import (
	"fmt"
	"net"
	"time"
)

// State represents the status of a target TCP port.
type State uint8

const (
	StateUnknown State = iota
	StateOpen
	StateClosed
	StateTimeout
	StateUnreachable
	StateCanceled
	StateError
)

// String returns the string representation of the port state
func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateTimeout:
		return "timeout"
	case StateUnreachable:
		return "unreachable"
	case StateCanceled:
		return "canceled"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// Result holds the scan outcome for a specific target port.
type Result struct {
	Host     string
	IP       net.IP
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}

func (r Result) String() string {
	if r.Err != nil {
		return fmt.Sprintf("%s (%s):%d [%s] in %v (err: %v)", r.Host, r.IP, r.Port, r.State, r.Duration, r.Err)
	}
	return fmt.Sprintf("%s (%s):%d [%s] in %v", r.Host, r.IP, r.Port, r.State, r.Duration)
}
