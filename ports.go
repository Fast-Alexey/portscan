package portscan

import (
	"errors"
	"sort"
)

var (
	ErrInvalidPort  = errors.New("port out of range (must be 1-65535)")
	ErrInvalidRange = errors.New("invalid port range: start must be <= end")
	ErrEmptyPorts   = errors.New("ports list is empty")
)

// PortProvider defines a contract for providing a list of validated ports.
type PortProvider interface {
	Ports() ([]uint16, error)
}

type staticPorts []uint16

func (p staticPorts) Ports() ([]uint16, error) {
	return deduplicateAndValidate(p)
}

type errorPortProvider struct {
	err error
}

func (e errorPortProvider) Ports() ([]uint16, error) {
	return nil, e.err
}

// Ports creates a provider from a list of individual port numbers.
func Ports(ports ...int) PortProvider {
	if len(ports) == 0 {
		return errorPortProvider{ErrEmptyPorts}
	}
	res := make([]uint16, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return errorPortProvider{ErrInvalidPort}
		}
		res = append(res, uint16(p))
	}
	return staticPorts(res)
}

// Range creates a provider for a continuous range of ports, inclusive.
func Range(start, end int) PortProvider {
	if start < 1 || end > 65535 {
		return errorPortProvider{ErrInvalidPort}
	}
	if start > end {
		return errorPortProvider{ErrInvalidRange}
	}

	ports := make([]uint16, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, uint16(p))
	}
	return staticPorts(ports)
}

// Combine combines multiple providers into a single list without duplicates.
func Combine(providers ...PortProvider) PortProvider {
	return combinedPorts(providers)
}

type combinedPorts []PortProvider

func (c combinedPorts) Ports() ([]uint16, error) {
	if len(c) == 0 {
		return nil, ErrEmptyPorts
	}
	var all []uint16
	for _, provider := range c {
		ports, err := provider.Ports()
		if err != nil {
			return nil, err
		}
		all = append(all, ports...)
	}
	return deduplicateAndValidate(all)
}

func deduplicateAndValidate(ports []uint16) ([]uint16, error) {
	if len(ports) == 0 {
		return nil, ErrEmptyPorts
	}

	seen := make(map[uint16]struct{}, len(ports))
	unique := make([]uint16, 0, len(ports))

	for _, p := range ports {
		if p == 0 {
			return nil, ErrInvalidPort
		}
		if _, exists := seen[p]; !exists {
			seen[p] = struct{}{}
			unique = append(unique, p)
		}
	}

	sort.Slice(unique, func(i, j int) bool { return unique[i] < unique[j] })
	return unique, nil
}
