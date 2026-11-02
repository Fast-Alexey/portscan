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

// WithConcurrency устанавливает максимальное количество одновременно проверяемых портов.
func WithConcurrency(n int) Option {
	return func(s *Scanner) error {
		if n <= 0 {
			return errors.New("concurrency must be greater than 0")
		}
		s.concurrency = n
		return nil
	}
}

// WithConnectTimeout задает таймаут на попытку установления TCP-соединения.
func WithConnectTimeout(d time.Duration) Option {
	return func(s *Scanner) error {
		if d <= 0 {
			return errors.New("connect timeout must be greater than 0")
		}
		s.timeout = d
		return nil
	}
}
