package portscan

import (
	"errors"
	"reflect"
	"testing"
)

func TestPorts_Validation(t *testing.T) {
	tests := []struct {
		name     string
		provider PortProvider
		want     []uint16
		wantErr  error
	}{
		{
			name:     "valid single list",
			provider: Ports(80, 443, 80),
			want:     []uint16{80, 443},
			wantErr:  nil,
		},
		{
			name:     "port zero error",
			provider: Ports(0, 80),
			want:     nil,
			wantErr:  ErrInvalidPort,
		},
		{
			name:     "port out of bound",
			provider: Ports(70000),
			want:     nil,
			wantErr:  ErrInvalidPort,
		},
		{
			name:     "valid range",
			provider: Range(80, 82),
			want:     []uint16{80, 81, 82},
			wantErr:  nil,
		},
		{
			name:     "reversed range",
			provider: Range(100, 50),
			want:     nil,
			wantErr:  ErrInvalidRange,
		},
		{
			name:     "combine providers with overlap",
			provider: Combine(Ports(80, 443), Range(80, 82)),
			want:     []uint16{80, 81, 82, 443},
			wantErr:  nil,
		},
		{
			name:     "empty ports list",
			provider: Ports(),
			want:     nil,
			wantErr:  ErrEmptyPorts,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.provider.Ports()
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
