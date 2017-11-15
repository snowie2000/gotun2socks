package gotun2socks

import (
	"bufio"
	"fmt"
	"io"
	"time"

	"log"

	"github.com/yinghuocho/gosocks"
)

const (
	userPassAuth = 0x02
)

// ServerAuthenticater 服务端鉴权对象
type ServerAuthenticater struct{}

// ServerAuthenticate 实现服务端鉴权接口
func (s *ServerAuthenticater) ServerAuthenticate(conn *gosocks.SocksConn) (err error) {
	return
}

// ClientAuthenticator 客户端鉴权对象
type ClientAuthenticator struct{}

// ClientAuthenticate 实现客户端鉴权接口
// 在拨号到服务端时会调用这个接口
func (p *ClientAuthenticator) ClientAuthenticate(conn *gosocks.SocksConn) (err error) {
	log.Println("ClientAuthenticate")
	// 设置发送数据超时
	conn.SetWriteDeadline(time.Now().Add(conn.Timeout))
	// 告诉服务端自己的认证方式
	var req [3]byte
	req[0] = gosocks.SocksVersion // socks 5
	req[1] = 0                    // 不需要认证
	req[2] = userPassAuth         // 用户名密码登录
	_, err = conn.Write(req[:])
	if err != nil {
		return
	}

	// 设置接收数据超时
	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	// 接收服务器应答
	var resp [2]byte
	r := bufio.NewReader(conn)
	_, err = io.ReadFull(r, resp[:2])
	if err != nil {
		return
	}
	// 服务器不支持用户名密码方式登录
	if resp[0] != gosocks.SocksVersion || resp[1] != userPassAuth {
		err = fmt.Errorf("Fail to pass anonymous authentication: (0x%02x, 0x%02x)", resp[0], resp[1])
		return
	}

	// 设置发送数据超时
	conn.SetWriteDeadline(time.Now().Add(conn.Timeout))

	// 构建用户名密码数据包
	name := []byte("username")
	pwd := []byte("password")
	nameLen := len(name)
	pwdLen := len(pwd)
	userInfo := [256]byte{0}
	userInfo[0] = 1
	userInfo[1] = byte(nameLen)        // 用户名长度
	userInfo[nameLen+2] = byte(pwdLen) // 密码长度
	// 写入用户名
	for i, b := range name {
		userInfo[i+2] = b
	}
	// 写入密码
	for i, b := range pwd {
		userInfo[nameLen+i+2+1] = b
	}

	_, err = conn.Write(userInfo[:])
	if err != nil {
		return
	}

	// 设置接收数据超时
	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	// 接收服务器应答
	r = bufio.NewReader(conn)
	_, err = io.ReadFull(r, resp[:2])
	if err != nil {
		return
	}
	// 服务器校验认证错误
	if resp[0] != gosocks.SocksVersion || resp[1] != 0x00 {
		err = fmt.Errorf("Fail to pass anonymous authentication: (0x%02x, 0x%02x)", resp[0], resp[1])
		return
	}

	return
}
