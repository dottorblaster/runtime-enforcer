package otlp

import "fmt"

type Protocol string

const (
	GRPC         Protocol = "grpc"
	HTTPProtobuf Protocol = "http/protobuf"
)

func Parse(s string) (Protocol, error) {
	switch Protocol(s) {
	case GRPC, HTTPProtobuf:
		return Protocol(s), nil
	default:
		return "", fmt.Errorf("unsupported protocol %q (supported: %q, %q)", s, GRPC, HTTPProtobuf)
	}
}
