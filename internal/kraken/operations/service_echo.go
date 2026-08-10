package operations

import (
	"io"
	"net"
)

func newEchoService(config map[string]string) (Service, error) {
	port, err := servicePort(config)
	if err != nil {
		return nil, err
	}
	metadata := ServiceMetadata{Service: "echo", Port: port, Config: config}
	return newTCPService(metadata, func(conn net.Conn) error {
		_, err := io.Copy(conn, conn)
		return err
	}), nil
}
