package fingerprint

import (
	"math"
	"testing"
)

func loadTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := Load("../../rules/rules.json")
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	return e
}

// TestIdentifySamples 覆盖题目示例中的全部 banner 类型及 unknown 场景。
func TestIdentifySamples(t *testing.T) {
	e := loadTestEngine(t)
	cases := []struct {
		name       string
		banner     string
		protocol   string
		product    string
		version    string
		os         string
		confidence float64
	}{
		{"openssh-ubuntu", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95},
		{"openssh-debian", "SSH-2.0-OpenSSH_9.3 Debian-1", "SSH", "OpenSSH", "9.3", "Debian", 0.95},
		{"openssh-old", "SSH-1.99-OpenSSH_4.3", "SSH", "OpenSSH", "4.3", "", 0.95},
		{"ssh-dropbear", "SSH-2.0-dropbear_2022.83", "SSH", "dropbear", "2022.83", "", 0.85},
		{"nginx", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html", "HTTP", "nginx", "1.24.0", "", 0.9},
		{"nginx-ubuntu", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)", "HTTP", "nginx", "1.18.0", "Ubuntu", 0.9},
		{"apache", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57", "HTTP", "Apache", "2.4.57", "", 0.9},
		{"apache-ubuntu", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)", "HTTP", "Apache", "2.4.41", "Ubuntu", 0.9},
		{"jetty", "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51", "HTTP", "Jetty", "9.4.51", "", 0.85},
		{"iis", "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0", "HTTP", "Microsoft-IIS", "10.0", "", 0.9},
		{"tomcat", "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1", "HTTP", "Apache-Coyote", "1.1", "", 0.8},
		{"http-no-server-header", "HTTP/1.1 200 OK\r\nContent-Type: text/html", "HTTP", "", "", "", 0.6},
		{"mysql-80", "J\x00\x00\x00\n8.0.32\x00", "MySQL", "MySQL", "8.0.32", "", 0.9},
		{"mysql-57", "J\x00\x00\x00\n5.7.42\x00", "MySQL", "MySQL", "5.7.42", "", 0.9},
		{"mariadb", "J\x00\x00\x00\n5.5.5-10.11.2-MariaDB\x00", "MySQL", "MariaDB", "5.5.5-10.11.2-MariaDB", "", 0.9},
		{"redis-err", "-ERR wrong number of arguments for 'get' command", "Redis", "Redis", "", "", 0.7},
		{"redis-pong", "+PONG", "Redis", "Redis", "", "", 0.7},
		{"redis-noauth", "-NOAUTH Authentication required.", "Redis", "Redis", "", "", 0.7},
		{"proftpd", "220 ProFTPD 1.3.7 Server (ProFTPD)", "FTP", "ProFTPD", "1.3.7", "", 0.9},
		{"vsftpd", "220 (vsFTPd 3.0.5)", "FTP", "vsFTPd", "3.0.5", "", 0.9},
		{"pureftpd", "220 Welcome to Pure-FTPd", "FTP", "Pure-FTPd", "", "", 0.8},
		{"tls10", "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1", "TLS", "", "1.0", "", 0.9},
		{"tls13", "\x16\x03\x04\x00\xa5\x01\x00\x00\xa1", "TLS", "", "1.3", "", 0.9},
		{"unknown-quit", "QUIT\r\n", "unknown", "", "", "", 0},
		{"unknown-empty", "", "unknown", "", "", "", 0},
		{"unknown-garbage", "\x01\x02\x03 random data", "unknown", "", "", "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// unknown 场景用无端口提示的端口（12345），避免触发端口降级识别
			port := 80
			if c.protocol == "unknown" {
				port = 12345
			}
			got := e.Identify(Target{IP: "1.2.3.4", Port: port, Banner: c.banner})
			if got.Protocol != c.protocol || got.Product != c.product || got.Version != c.version || got.OSHint != c.os {
				t.Errorf("banner=%q 识别结果=%+v，期望 protocol=%s product=%s version=%s os=%s",
					c.banner, got, c.protocol, c.product, c.version, c.os)
			}
			if math.Abs(got.Confidence-c.confidence) > 1e-9 {
				t.Errorf("banner=%q confidence=%v，期望 %v", c.banner, got.Confidence, c.confidence)
			}
		})
	}
}

// TestIdentifyPortFallback banner 未识别时按端口降级，置信度不超过 0.5。
func TestIdentifyPortFallback(t *testing.T) {
	e := loadTestEngine(t)
	got := e.Identify(Target{IP: "1.2.3.4", Port: 6379, Banner: "*2\r\n$4\r\nPING"})
	if got.Protocol != "Redis" || got.Confidence > 0.5 {
		t.Errorf("端口降级识别失败: %+v", got)
	}
}

// TestIdentifyAllKeepsOrder 批量识别保持输入顺序。
func TestIdentifyAllKeepsOrder(t *testing.T) {
	e := loadTestEngine(t)
	targets := []Target{
		{IP: "a", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		{IP: "b", Port: 12345, Banner: "QUIT\r\n"},
	}
	got := e.IdentifyAll(targets)
	if len(got) != 2 || got[0].IP != "a" || got[1].IP != "b" || got[1].Protocol != "unknown" {
		t.Errorf("批量识别顺序或结果错误: %+v", got)
	}
}

// TestLoadErrors 规则文件非法时报错而不是 panic。
func TestLoadErrors(t *testing.T) {
	if _, err := Load("nonexistent.json"); err == nil {
		t.Error("文件不存在应报错")
	}
}
