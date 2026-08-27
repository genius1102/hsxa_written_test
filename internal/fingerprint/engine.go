// Package fingerprint 实现基于规则的 Banner 指纹识别引擎。
// 识别规则全部来自外部 JSON 文件（rules/rules.json），与程序代码完全解耦：
// 修改规则无需重新编译或重建镜像，只需替换规则文件并重启服务。
package fingerprint

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
)

// portHintMaxConfidence 是"仅凭端口提示识别"时的置信度上限。
// banner 正则未命中、仅端口匹配时使用，避免把不确定结果伪装成高置信结果。
const portHintMaxConfidence = 0.5

// Target 是扫描原始数据条目：ip、port、banner。
type Target struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result 是单条识别结果，字段与题目要求的输出格式一致。
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// rule 是单条识别规则。regex 支持命名分组 product/version/os，
// 命中后分组值会覆盖同名静态字段；banner 未命中时按 ports 端口提示降级识别。
type rule struct {
	ID         string  `json:"id"`
	Priority   int     `json:"priority"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
	Ports      []int   `json:"ports"`
	Regex      string  `json:"regex"`

	re *regexp.Regexp
}

type rulesFile struct {
	Version int    `json:"version"`
	Rules   []rule `json:"rules"`
}

// Engine 持有按优先级排序后的规则列表，并发安全（只读）。
type Engine struct {
	rules []rule
}

// Load 从 JSON 规则文件构建引擎。任何一条规则非法都会返回明确错误，绝不静默跳过。
func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取规则文件失败: %w", err)
	}
	var rf rulesFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("规则文件不是合法 JSON: %w", err)
	}
	if len(rf.Rules) == 0 {
		return nil, errors.New("规则文件为空，至少需要一条规则")
	}

	e := &Engine{rules: make([]rule, 0, len(rf.Rules))}
	for _, r := range rf.Rules {
		if r.ID == "" {
			return nil, errors.New("存在缺少 id 的规则")
		}
		if r.Protocol == "" {
			return nil, fmt.Errorf("规则 %q 缺少 protocol", r.ID)
		}
		if r.Confidence < 0 || r.Confidence > 1 {
			return nil, fmt.Errorf("规则 %q 的 confidence 须在 0~1 之间", r.ID)
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return nil, fmt.Errorf("规则 %q 正则非法: %w", r.ID, err)
		}
		r.re = re
		e.rules = append(e.rules, r)
	}
	// 优先级大者先匹配；同优先级保持文件内顺序
	sort.SliceStable(e.rules, func(i, j int) bool { return e.rules[i].Priority > e.rules[j].Priority })
	return e, nil
}

// RuleCount 返回已加载的规则数量。
func (e *Engine) RuleCount() int { return len(e.rules) }

// Identify 识别单条数据。认不出时返回 protocol="unknown" 的结果，绝不报错。
func (e *Engine) Identify(t Target) Result {
	// 第一轮：banner 正则匹配（优先级从高到低，首个命中即返回）
	for i := range e.rules {
		r := &e.rules[i]
		if m := r.re.FindStringSubmatch(t.Banner); m != nil {
			return r.buildResult(t, m)
		}
	}
	// 第二轮：banner 未识别，按端口提示降级识别（低置信度）
	for i := range e.rules {
		r := &e.rules[i]
		if containsPort(r.Ports, t.Port) {
			res := r.buildResult(t, nil)
			res.Confidence = math.Min(res.Confidence, portHintMaxConfidence)
			return res
		}
	}
	return Result{IP: t.IP, Port: t.Port, Protocol: "unknown"}
}

// IdentifyAll 批量识别，输入顺序与输出顺序一一对应。
func (e *Engine) IdentifyAll(targets []Target) []Result {
	out := make([]Result, 0, len(targets))
	for _, t := range targets {
		out = append(out, e.Identify(t))
	}
	return out
}

// buildResult 用规则静态字段构造结果，m 为 nil（端口降级）时直接用静态字段。
func (r *rule) buildResult(t Target, m []string) Result {
	res := Result{
		IP:         t.IP,
		Port:       t.Port,
		Protocol:   r.Protocol,
		Product:    r.Product,
		Version:    r.Version,
		OSHint:     r.OSHint,
		Confidence: r.Confidence,
	}
	if m == nil {
		return res
	}
	// 正则命名分组命中时覆盖静态字段，规则编写更灵活
	for i, name := range r.re.SubexpNames() {
		if i == 0 || i >= len(m) || m[i] == "" {
			continue
		}
		switch name {
		case "product":
			res.Product = m[i]
		case "version":
			res.Version = m[i]
		case "os":
			res.OSHint = m[i]
		}
	}
	return res
}

func containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}
