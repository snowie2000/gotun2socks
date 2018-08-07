package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/snowie2000/gotun2socks"
	"github.com/snowie2000/gotun2socks/tun"
)

func main() {
	var tunDevice string
	var tunAddr string
	var tunMask string
	var tunGW string
	var tunDNS string
	var localSocksAddr string
	var publicOnly bool
	var enableDnsCache bool
	flag.StringVar(&tunDevice, "tun-device", "tun0", "tun device name")
	flag.StringVar(&tunAddr, "tun-address", "10.0.0.2", "tun device address")
	flag.StringVar(&tunMask, "tun-mask", "255.255.255.0", "tun device netmask")
	flag.StringVar(&tunGW, "tun-gw", "10.0.0.1", "tun device gateway")
	flag.StringVar(&tunDNS, "tun-dns", "8.8.8.8,8.8.4.4", "tun dns servers")
	flag.StringVar(&localSocksAddr, "local-socks-addr", "socks5://username:password@127.0.0.1:10800",
		"local SOCKS proxy address")
	flag.BoolVar(&publicOnly, "public-only", false, "only forward packets with public address destination")
	flag.BoolVar(&enableDnsCache, "enable-dns-cache", false, "enable local dns cache if specified")
	flag.Parse()

	dnsServers := strings.Split(tunDNS, ",")
	f, e := tun.OpenTunDevice(tunDevice, tunAddr, tunGW, tunMask, dnsServers)
	if e != nil {
		log.Fatal(e)
	}

	sock, err := gotun2socks.New(f, localSocksAddr, dnsServers, publicOnly, enableDnsCache)
	if e != nil {
		panic(err)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		s := <-ch
		switch s {
		default:
			sock.Stop()
		}
	}()

	sock.Run()
}
