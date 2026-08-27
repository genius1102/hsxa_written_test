// banner-fingerprint server：提供 POST /fingerprint（批量识别）与 GET /health（健康检查）。
// 生产级要素：结构化日志、panic 恢复、请求体大小限制、超时控制、优雅停机。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/genius1102/hsxa_written_test/internal/fingerprint"
)

const (
	defaultListenAddr = ":8080"
	defaultRulesPath  = "rules/rules.json"
	maxBodyBytes      = 10 << 20 // 请求体上限 10MB
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(os.Getenv("LOG_LEVEL")),
	})))

	// 识别规则从外部文件加载，与代码解耦（容器内默认挂载 /etc/bannerf/rules.json）
	rulesPath := envOr("RULES_PATH", defaultRulesPath)
	engine, err := fingerprint.Load(rulesPath)
	if err != nil {
		slog.Error("加载指纹规则失败", "path", rulesPath, "err", err)
		os.Exit(1)
	}
	slog.Info("指纹规则已加载", "path", rulesPath, "count", engine.RuleCount())

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		handleHealth(w, engine)
	})
	mux.Handle("POST /fingerprint", withRecover(withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleFingerprint(w, r, engine)
	}))))

	srv := &http.Server{
		Addr:              envOr("LISTEN_ADDR", defaultListenAddr),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		slog.Info("server 启动", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server 异常退出", "err", err)
			os.Exit(1)
		}
	}()

	// 优雅停机：收到 SIGINT/SIGTERM 后等待在途请求完成（最多 10s）
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("收到退出信号，优雅停机中")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("优雅停机失败", "err", err)
	}
	slog.Info("server 已停止")
}

// handleHealth 健康检查，附带当前已加载的规则数，便于运维观察。
func handleHealth(w http.ResponseWriter, engine *fingerprint.Engine) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "rules": engine.RuleCount()})
}

// handleFingerprint 批量识别。请求体兼容裸 JSON 数组或 {"targets": [...]} 对象。
// 参数非法返回 400 及明确错误信息；单条 banner 认不出返回 protocol="unknown"，绝不报错。
func handleFingerprint(w http.ResponseWriter, r *http.Request, engine *fingerprint.Engine) {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type 须为 application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "读取请求体失败: "+err.Error())
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "请求体为空")
		return
	}

	var targets []fingerprint.Target
	switch body[0] {
	case '[':
		if err := json.Unmarshal(body, &targets); err != nil {
			writeError(w, http.StatusBadRequest, "请求体 JSON 解析失败: "+err.Error())
			return
		}
	case '{':
		var req struct {
			Targets []fingerprint.Target `json:"targets"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "请求体 JSON 解析失败: "+err.Error())
			return
		}
		targets = req.Targets
	default:
		writeError(w, http.StatusBadRequest, `请求体须为 JSON 数组或 {"targets": [...]} 对象`)
		return
	}

	// 参数校验：ip/port 必填且合法，banner 允许为空（识别为 unknown）
	for i := range targets {
		if targets[i].IP == "" {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("第 %d 条数据缺少 ip 字段", i+1))
			return
		}
		if targets[i].Port < 1 || targets[i].Port > 65535 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("第 %d 条数据 port 非法（须在 1~65535 之间）: %d", i+1, targets[i].Port))
			return
		}
	}

	results := engine.IdentifyAll(targets)
	writeJSON(w, http.StatusOK, results)
}

// ---------- 通用工具 ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// statusRecorder 记录响应状态码，供访问日志使用。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// withAccessLog 打印每次请求的方法、路径、状态码、耗时。
func withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration", time.Since(start).String(), "remote", r.RemoteAddr)
	})
}

// withRecover 兜底恢复 panic，返回 500 而不是让进程崩溃。
func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				slog.Error("panic recovered", "panic", p, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "服务器内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
