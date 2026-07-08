package script

import (
	"fmt"
	"net"
)

func takeTCPScriptConn(caller string, conn *scriptConn, owner string) (net.Conn, error) {
	if conn == nil || conn.protocol != "tcp" {
		return nil, fmt.Errorf("%s requires a TCP connection from kraken/socket.tcp", caller)
	}
	return conn.takeNetConn(owner)
}
