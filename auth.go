package gotun2socks

import (
	"bufio"
	"fmt"
	"io"
	"time"

	"github.com/yinghuocho/gosocks"
)

// ClientAuthenticator 客户端鉴权对象
type ClientAuthenticator struct {
	Version  byte
	Username string
	Password string
}

// NewClientAuthenticator 初始化客户端鉴权对象
// 外部调用者传入用户名密码，本实例从参数读取
func NewClientAuthenticator(u, p string) *ClientAuthenticator {
	return &ClientAuthenticator{
		Version:  gosocks.SocksVersion,
		Username: u,
		Password: p,
	}
}

// String 实现fmt的String接口，方便打印结构体内部信息
func (p *ClientAuthenticator) String() string {
	return fmt.Sprintf("%d %s %s", p.Version, p.Username, p.Password)
}

// ClientAuthenticate 实现客户端鉴权接口
// 在拨号到服务端时会调用这个接口
func (p *ClientAuthenticator) ClientAuthenticate(conn *gosocks.SocksConn) (err error) {
	// 设置发送数据超时
	conn.SetWriteDeadline(time.Now().Add(conn.Timeout))
	// 告诉服务端自己的认证方式
	var req [3]byte
	req[0] = gosocks.SocksVersion // socks 5
	req[1] = 1                    // 验证方法的个数
	req[2] = 2                    // 用户名密码登录 0x02
	if _, err = conn.Write(req[:]); err != nil {
		return fmt.Errorf("请求服务器认证方式错误: %v", err)
	}

	// 设置接收数据超时
	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	// 接收服务器应答
	var resp [2]byte
	r := bufio.NewReader(conn)
	_, err = io.ReadFull(r, resp[:2])
	if err != nil {
		return fmt.Errorf("接收服务器应答错误: %v", err)
	}
	// 服务器不支持用户名密码方式登录
	if resp[0] != gosocks.SocksVersion || resp[1] != 0x02 {
		return fmt.Errorf("服务器不支持用户名密码方式登录: (0x%02x, 0x%02x)", resp[0], resp[1])
	}

	// 设置发送数据超时
	conn.SetWriteDeadline(time.Now().Add(conn.Timeout))

	// 构建用户名密码数据包
	b := make([]byte, 513)
	b[0] = 0x01
	uLen := len(p.Username)
	b[1] = byte(uLen)
	idx := 2 + uLen
	copy(b[2:idx], p.Username)

	pLen := len(p.Password)
	b[idx] = byte(pLen)
	idx++
	copy(b[idx:idx+pLen], p.Password)
	idx += pLen

	if _, err = conn.Write(b[:idx]); err != nil {
		return fmt.Errorf("发送密码错误： %v", err)
	}

	// 设置接收数据超时
	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	// 接收服务器应答
	r = bufio.NewReader(conn)

	if _, err = io.ReadFull(r, resp[:2]); err != nil {
		return fmt.Errorf("接收服务器应答错误： %v", err)
	}
	// 服务器校验认证错误
	if resp[0] != 0x01 {
		return fmt.Errorf("服务器鉴权错误: (0x%02x, 0x%02x)", resp[0], resp[1])
	}

	return
}
