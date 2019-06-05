package main

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/ginuerzh/gosocks5"
)

const (
	// MethodTLS is an extended SOCKS5 method for TLS.
	MethodTLS uint8 = 0x80
	// MethodTLSAuth is an extended SOCKS5 method for TLS+AUTH.
	MethodTLSAuth uint8 = 0x82
)

const (
	// CmdUDPTun is an extended SOCKS5 method for UDP over TCP.
	CmdUDPTun uint8 = 0xF3
)

var (
	DefaultTLSConfig *tls.Config
	Debug            bool = false
	// KeepAliveTime is the keep alive time period for TCP connection.
	KeepAliveTime = 180 * time.Second
	// DialTimeout is the timeout of dial.
	DialTimeout = 30 * time.Second
	// ReadTimeout is the timeout for reading.
	ReadTimeout = 30 * time.Second
	// WriteTimeout is the timeout for writing.
	WriteTimeout = 60 * time.Second
	// PingTimeout is the timeout for pinging.
	PingTimeout = 30 * time.Second
	// PingRetries is the reties of ping.
	PingRetries = 1
	// default udp node TTL in second for udp port forwarding.
	defaultTTL = 60 * time.Second

	tinyBufferSize   = 128
	smallBufferSize  = 1 * 1024  // 1KB small buffer
	mediumBufferSize = 8 * 1024  // 8KB medium buffer
	largeBufferSize  = 32 * 1024 // 32KB large buffer
)

// =-=-=-=-=-=-=- socks5 connector -=-=-=-=-=-=-=

type Connector interface {
	Connect(conn net.Conn, addr string) (net.Conn, error)
}

type socks5Connector struct {
	noHandShake bool
}

// SOCKS5Connector creates a connector for SOCKS5 proxy client.
// It accepts an optional auth info for SOCKS5 Username/Password Authentication.
func SOCKS5Connector() Connector {
	return &socks5Connector{}
}

func (c *socks5Connector) Connect(conn net.Conn, addr string) (net.Conn, error) {
	cc := gosocks5.ClientConn(conn, nil)
	if c.noHandShake { // fake client hand shake handled by node
		cc.IgnoreHandleshake()
	} else {
		if err := cc.Handleshake(); err != nil {
			return nil, err
		}
	}
	conn = cc
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(port)
	req := gosocks5.NewRequest(gosocks5.CmdConnect, &gosocks5.Addr{
		Type: gosocks5.AddrDomain,
		Host: host,
		Port: uint16(p),
	})
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Println("[socks5]", req)
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Println("[socks5]", reply)
	}

	if reply.Rep != gosocks5.Succeeded {
		return nil, errors.New("Service unavailable")
	}

	return conn, nil
}
