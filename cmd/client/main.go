// banner-fingerprint client：独立程序，读取本地 JSON 文件 → 发送 server → 表格展示识别结果。
// 兼容裸 JSON 数组与 {"targets": [...]} 两种输入格式，并容忍扫描原始数据中的 \xHH 字节写法。
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/genius1102/hsxa_written_test/internal/fingerprint"
)

// 扫描原始数据中常见 \xHH 写法（非标准 JSON 转义），解析前先还原为真实字节
var hexEscapeRe = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

func main() {
	serverURL := flag.String("server", envOr("SERVER_URL", "http://127.0.0.1:8080"), "fingerprint server 地址")
	filePath := flag.String("file", envOr("INPUT_FILE", "samples/input.json"), "输入数据文件路径（JSON 数组或 {\"targets\": [...]}）")
	asJSON := flag.Bool("json", false, "结果以 JSON 输出（默认表格）")
	timeout := flag.Duration("timeout", 30*time.Second, "HTTP 请求超时时间")
	flag.Parse()

	targets, err := readInput(*filePath)
	if err != nil {
		fatalf("读取输入文件失败: %v", err)
	}
	if len(targets) == 0 {
		fatalf("输入文件中没有数据: %s", *filePath)
	}

	results, err := identify(*serverURL, targets, *timeout)
	if err != nil {
		fatalf("调用 server 失败: %v", err)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fatalf("输出 JSON 失败: %v", err)
		}
		return
	}

	printTable(results)
}

// readInput 读取输入文件。文件不存在 / 空文件 / JSON 非法时返回明确错误，不 panic。
func readInput(path string) ([]fingerprint.Target, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("文件不存在或不可读 (%s): %w", path, err)
	}
	// 扫描原始数据中常见的 \xHH 写法（非标准 JSON 转义）→ 标准 JSON 转义 \u00HH，
	// 再由 json 解码器还原为真实字节（Go 的 JSON 解码器不接受字符串内裸控制字符）
	raw = hexEscapeRe.ReplaceAllFunc(raw, func(m []byte) []byte {
		b, _ := hex.DecodeString(string(m[2:]))
		return []byte(fmt.Sprintf(`\u00%02x`, b[0]))
	})
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("文件内容为空 (%s)", path)
	}

	var targets []fingerprint.Target
	switch raw[0] {
	case '[':
		if err := json.Unmarshal(raw, &targets); err != nil {
			return nil, fmt.Errorf("JSON 解析失败: %w", err)
		}
	case '{':
		var req struct {
			Targets []fingerprint.Target `json:"targets"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, fmt.Errorf("JSON 解析失败: %w", err)
		}
		targets = req.Targets
	default:
		return nil, fmt.Errorf(`文件须为 JSON 数组或 {"targets": [...]} 对象`)
	}
	return targets, nil
}

// identify 将目标列表 POST 到 server，返回识别结果。
func identify(serverURL string, targets []fingerprint.Target, timeout time.Duration) ([]fingerprint.Result, error) {
	payload, err := json.Marshal(map[string]any{"targets": targets})
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(strings.TrimRight(serverURL, "/")+"/fingerprint", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server 返回 %d: %s", resp.StatusCode, string(body))
	}

	var results []fingerprint.Result
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	return results, nil
}

func printTable(results []fingerprint.Result) {
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
	known := 0
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n", r.IP, r.Port, r.Protocol, r.Product, r.Version, r.OSHint, r.Confidence)
		if r.Protocol != "unknown" {
			known++
		}
	}
	_ = w.Flush()
	fmt.Printf("\n共 %d 条，成功识别 %d 条，unknown %d 条\n", len(results), known, len(results)-known)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "错误: "+format+"\n", args...)
	os.Exit(1)
}
