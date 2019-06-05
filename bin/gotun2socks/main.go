package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jackpal/gateway"
	"github.com/snowie2000/gotun2socks"
	"github.com/snowie2000/gotun2socks/tun"
)

func getSocks5RealAddr(localSocksAddr string) (ip string) {
	ip = ""
	s5con := SOCKS5Connector()
	if u, e := url.Parse(localSocksAddr); e == nil {
		if con, e := net.Dial("tcp", u.Host); e == nil {
			defer con.Close()
			if dconn, e := s5con.Connect(con, "api.ipify.org:80"); e == nil {
				defer dconn.Close()
				req, _ := http.NewRequest(http.MethodGet, "http://api.ipify.org/", nil)
				if req.Write(dconn) == nil {
					resp, e := http.ReadResponse(bufio.NewReader(dconn), req)
					if e == nil {
						defer resp.Body.Close()
						buf := make([]byte, resp.ContentLength)
						if _, e := io.ReadFull(resp.Body, buf); e == nil {
							ip = string(buf)
							log.Println("socks5 public address:", ip)
						}
					}
				}
			}
		}
	}
	return ip
}
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
	flag.StringVar(&localSocksAddr, "local-socks-addr", "127.0.0.1:1080", "local SOCKS proxy address")
	flag.BoolVar(&publicOnly, "public-only", false, "only forward packets with public address destination")
	flag.BoolVar(&enableDnsCache, "enable-dns-cache", false, "enable local dns cache if specified")
	flag.Parse()

	dnsServers := strings.Split(tunDNS, ",")
	f, e := tun.OpenTunDevice(tunDevice, tunAddr, tunGW, tunMask, dnsServers)
	if e != nil {
		log.Fatal(e)
	}
	tun := gotun2socks.New(f, localSocksAddr, dnsServers, publicOnly, enableDnsCache)

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
			tun.Stop()
		}
	}()

	tun.Run()
}
