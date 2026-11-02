package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	ErrEmptyHosts = errors.New("hosts list cannot be empty")
	ErrEmptyHost  = errors.New("host cannot be empty")
)

type Scanner struct {
	concurrency int
	timeout     time.Duration
}

// New создает новый экземпляр сканера с переданными опциями.
func New(opts ...Option) (*Scanner, error) {
	s := &Scanner{
		concurrency: defaultConcurrency,
		timeout:     defaultConnectTimeout,
	}

	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	return s, nil
}

type scanTask struct {
	host string
	ip   net.IP
	port uint16
}

// Scan запускает сканирование переданных хостов и портов.
func (s *Scanner) Scan(ctx context.Context, hosts []string, portProvider PortProvider) (<-chan Result, error) {
	if len(hosts) == 0 {
		return nil, ErrEmptyHosts
	}

	ports, err := portProvider.Ports()
	if err != nil {
		return nil, fmt.Errorf("invalid ports specification: %w", err)
	}

	tasks, err := s.resolveTargets(ctx, hosts, ports)
	if err != nil {
		return nil, err
	}

	results := make(chan Result, s.concurrency)

	go func() {
		defer close(results)

		tasksChan := make(chan scanTask, s.concurrency)
		var wg sync.WaitGroup

		workerCount := s.concurrency
		if len(tasks) < workerCount {
			workerCount = len(tasks)
		}

		// Запуск пула воркеров
		wg.Add(workerCount)
		for i := 0; i < workerCount; i++ {
			go func() {
				defer wg.Done()
				for task := range tasksChan {
					res := s.dialTask(ctx, task)
					select {
					case <-ctx.Done():
						return
					case results <- res:
					}
				}
			}()
		}

		// Подача задач в воркеры
	feedLoop:
		for _, task := range tasks {
			select {
			case <-ctx.Done():
				break feedLoop
			case tasksChan <- task:
			}
		}
		close(tasksChan)

		wg.Wait()
	}()

	return results, nil
}

func (s *Scanner) dialTask(ctx context.Context, task scanTask) Result {
	address := net.JoinHostPort(task.ip.String(), fmt.Sprintf("%d", task.port))

	dialer := net.Dialer{
		Timeout: s.timeout,
	}

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	duration := time.Since(start)

	state, classifiedErr := classifyError(err, ctx)
	if conn != nil {
		_ = conn.Close()
	}

	return Result{
		Host:     task.host,
		IP:       task.ip,
		Port:     task.port,
		State:    state,
		Duration: duration,
		Err:      classifiedErr,
	}
}

func (s *Scanner) resolveTargets(ctx context.Context, hosts []string, ports []uint16) ([]scanTask, error) {
	var tasks []scanTask
	resolver := net.DefaultResolver

	// Защита от дубликатов хостов
	seenHosts := make(map[string]struct{}, len(hosts))

	for _, host := range hosts {
		if host == "" {
			return nil, ErrEmptyHost
		}
		if _, exists := seenHosts[host]; exists {
			continue
		}
		seenHosts[host] = struct{}{}

		// Если это уже корректный IP (IPv4 или IPv6)
		if ip := net.ParseIP(host); ip != nil {
			for _, port := range ports {
				tasks = append(tasks, scanTask{host: host, ip: ip, port: port})
			}
			continue
		}

		// Если это доменное имя
		ips, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve host %q: %w", host, err)
		}

		for _, ip := range ips {
			for _, port := range ports {
				tasks = append(tasks, scanTask{host: host, ip: ip, port: port})
			}
		}
	}

	return tasks, nil
}
