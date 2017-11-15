package gotun2socks

import (
	"testing"
)

func TestUserInfo(t *testing.T) {
	// 构建用户名密码数据包
	name := []byte("username")
	pwd := []byte("password")
	nameLen := len(name)
	pwdLen := len(pwd)
	userInfo := [255]byte{0}
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

	t.Log(userInfo)
}
