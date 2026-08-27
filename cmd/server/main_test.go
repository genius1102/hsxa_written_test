package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/genius1102/hsxa_written_test/internal/fingerprint"
)

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	engine, err := fingerprint.Load("../../rules/rules.json")
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		handleHealth(w, engine)
	})
	mux.Handle("POST /fingerprint", withRecover(withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleFingerprint(w, r, engine)
	}))))
	return mux
}

func TestHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	newTestHandler(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health 返回 %d: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"ok"`)) {
		t.Fatalf("health 响应内容异常: %s", rec.Body.String())
	}
}

func TestFingerprintBareArray(t *testing.T) {
	payload := []byte(`[
		{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		{"ip":"1.2.3.9","port":21,"banner":"220 ProFTPD 1.3.7 Server (ProFTPD)"},
		{"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}
	]`)
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	newTestHandler(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("返回 %d: %s", rec.Code, rec.Body.String())
	}
	var results []fingerprint.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("期望 3 条结果，得到 %d", len(results))
	}
	if results[0].Product != "OpenSSH" || results[0].Version != "8.9p1" || results[0].OSHint != "Ubuntu" {
		t.Errorf("SSH 识别错误: %+v", results[0])
	}
	if results[1].Product != "ProFTPD" {
		t.Errorf("FTP 识别错误: %+v", results[1])
	}
	if results[2].Protocol != "unknown" {
		t.Errorf("期望 unknown，得到: %+v", results[2])
	}
}

func TestFingerprintWrappedObject(t *testing.T) {
	payload := []byte(`{"targets":[{"ip":"1.2.3.8","port":6379,"banner":"-ERR wrong number of arguments for 'get' command"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	newTestHandler(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("返回 %d: %s", rec.Code, rec.Body.String())
	}
	var results []fingerprint.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(results) != 1 || results[0].Protocol != "Redis" || results[0].Product != "Redis" {
		t.Errorf("Redis 识别错误: %+v", results)
	}
}

// TestFingerprintBinaryBanner MySQL 握手包含 NUL 字节，用 json.Marshal 构造请求体，
// 验证 server 对二进制 banner 的处理（json.Marshal 会自动把 NUL 转成 ）。
func TestFingerprintBinaryBanner(t *testing.T) {
	targets := []fingerprint.Target{{
		IP:     "1.2.3.7",
		Port:   3306,
		Banner: "J\x00\x00\x00\n8.0.32\x00",
	}}
	payload, err := json.Marshal(targets)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	newTestHandler(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("返回 %d: %s", rec.Code, rec.Body.String())
	}
	var results []fingerprint.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(results) != 1 || results[0].Product != "MySQL" || results[0].Version != "8.0.32" {
		t.Errorf("MySQL 识别错误: %+v", results)
	}
}

func TestFingerprintBadJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	newTestHandler(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 JSON 期望 400，得到 %d", rec.Code)
	}
}

func TestFingerprintInvalidPort(t *testing.T) {
	payload := []byte(`[{"ip":"1.2.3.4","port":99999,"banner":"x"}]`)
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	newTestHandler(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法端口期望 400，得到 %d: %s", rec.Code, rec.Body.String())
	}
}

func TestFingerprintEmptyArray(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewReader([]byte(`[]`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	newTestHandler(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("空数组期望 200，得到 %d", rec.Code)
	}
}
