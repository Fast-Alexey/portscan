package portscan

import (
	"errors"
	"time"
)

type Option func(*Scanner) error

const (
	defaultConcurrency    = 100
	defaultConnectTimeout = 1 * time.Second
)

// WithConcurrency sets the maximum number of ports to be checked simultaneously.
func WithConcurrency(n int) Option {
	return func(s *Scanner) error {
		if n <= 0 {
			return errors.New("concurrency must be greater than 0")
		}
		s.concurrency = n
		return nil
	}
}

// WithConnectTimeout sets a timeout for the attempt to establish a TCP connection.
func WithConnectTimeout(d time.Duration) Option {
	return func(s *Scanner) error {
		if d <= 0 {
			return errors.New("connect timeout must be greater than 0")
		}
		s.timeout = d
		return nil
	}
}
