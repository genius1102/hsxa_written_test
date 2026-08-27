# Banner 指纹识别系统（banner-fingerprint）

接收一批网络扫描原始数据（`ip`、`port`、`banner`），识别出对应的协议、软件与版本信息。Golang 实现，client + server 架构，Docker Compose 一键启动。

## 架构

```
┌──────────────┐   POST /fingerprint   ┌─────────────────────┐
│    client     │ ────────────────────► │       server        │
│  读本地JSON文件 │  （内部网络 server:8080）│  Go net/http + 规则引擎 │
│  表格展示结果   │ ◄──────────────────── │  识别规则外部JSON文件   │
└──────────────┘      识别结果JSON       └─────────────────────┘
                                           GET /health（健康检查）
```

- **server**：`POST /fingerprint`（批量识别）、`GET /health`（健康检查）
- **client**：独立程序，读取本地 JSON 文件 → 发送 server → 表格/JSON 展示结果
- **规则与代码解耦**：识别规则全部在 `rules/rules.json`，正则 + 优先级 + 端口提示，改规则无需重新编译

## 快速开始（Docker Compose 一键启动）

```bash
docker compose up -d --build
```

- server 启动并通过健康检查后，client 自动运行一次并输出识别结果：

```bash
docker compose logs client      # 查看识别结果（表格）
docker compose ps               # 查看服务状态（server 应为 healthy）
curl http://127.0.0.1:8080/health   # 宿主侧验证健康检查
```

- 换一批数据识别：把 JSON 文件放进 `samples/` 目录后重跑 client：

```bash
docker compose run --rm client -file /data/你的文件.json -server http://server:8080
# 或直接修改 samples/input.json 后：docker compose run --rm client
```

## 本地裸跑（无需 Docker）

```bash
# 终端 1：启动 server（默认 :8080，规则默认 rules/rules.json）
go run ./cmd/server

# 终端 2：运行 client
go run ./cmd/client -file samples/input.json -server http://127.0.0.1:8080
# JSON 输出：go run ./cmd/client -file samples/input.json -json
```

## API 说明

### `POST /fingerprint` 批量识别

请求体兼容两种格式（裸数组或 `{"targets": [...]}` 包装对象）：

```json
[
  {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip": "1.2.3.23", "port": 12345, "banner": "QUIT\r\n"}
]
```

响应（字段与顺序与输入一一对应）：

```json
[
  {"ip": "1.2.3.4", "port": 22, "protocol": "SSH", "product": "OpenSSH", "version": "8.9p1", "os_hint": "Ubuntu", "confidence": 0.95},
  {"ip": "1.2.3.23", "port": 12345, "protocol": "unknown", "product": "", "version": "", "os_hint": "", "confidence": 0}
]
```

错误约定：请求体非法 JSON / 缺少 ip / port 超出 1~65535 → `400` + `{"error": "明确原因"}`；banner 认不出 → 正常返回 `protocol: "unknown"`，服务绝不因此报错或崩溃。

curl 示例：

```bash
curl -s -X POST http://127.0.0.1:8080/fingerprint \
  -H "Content-Type: application/json" \
  -d '[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]'
```

### `GET /health` 健康检查

```json
{"status": "ok", "rules": 18}
```

## 识别能力与规则

`rules/rules.json` 中每条规则包含：`id`、`priority`（大者先匹配）、`protocol`/`product`/`version`/`os_hint` 静态字段、`confidence`（0~1）、`ports`（端口提示）、`regex`（Go 正则，支持命名分组 `product`/`version`/`os`，命中后覆盖静态字段）。

识别流程：① banner 正则按优先级匹配，首个命中即返回；② 未命中则按 `ports` 端口提示降级识别（置信度上限 0.5）；③ 仍无结果 → `protocol: "unknown"`。

当前覆盖：**SSH**（OpenSSH 及 dropbear 等通用实现，含 `os_hint`）、**HTTP**（nginx / Apache / Jetty / IIS 及通用 Server 头、无 Server 头的 HTTP 响应）、**MySQL**（含 MariaDB 变体，二进制握手包解析）、**Redis**（`+PONG`/`-ERR`/`-NOAUTH` 等单行响应）、**FTP**（ProFTPD / vsFTPd / Pure-FTPd）、**TLS**（按 ClientHello 记录头识别 1.0~1.3）。

新增规则示例（无需改代码、无需重建镜像，改 `rules/rules.json` 后重启容器）：

```json
{
  "id": "http-caddy",
  "priority": 700,
  "protocol": "HTTP",
  "product": "Caddy",
  "confidence": 0.9,
  "ports": [80, 443],
  "regex": "(?im)^Server:\\s*(?P<product>Caddy)/(?P<version>[0-9][0-9A-Za-z._+\\-]*)"
}
```

字节级匹配写法：JSON 中写作 `\\xHH`（解码后为 Go 正则 `\xHH`），如 MySQL 握手包 `^\\x4a\\x00\\x00\\x00\\x0a(?P<version>[^\\x00]+)`。

## 配置项（环境变量）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `SERVER_PORT` | `8080` | server 对宿主机暴露的端口（compose） |
| `LOG_LEVEL` | `info` | server 日志级别：debug/info/warn/error |
| `LISTEN_ADDR` | `:8080` | server 监听地址 |
| `RULES_PATH` | `rules/rules.json` | 规则文件路径（容器内为 `/etc/bannerf/rules.json`） |
| `SERVER_URL` | `http://127.0.0.1:8080` | client 访问的 server 地址（容器内 `http://server:8080`） |
| `INPUT_FILE` | `samples/input.json` | client 输入文件（容器内 `/data/input.json`） |

`cp .env.example .env` 后按需修改，compose 自动加载。

## 测试

```bash
go test ./...   # 单元测试：规则引擎（覆盖示例全部 banner 类型）+ server 接口（httptest）
```

## 生产级部署要点（评估重点自查）

- **容器间访问收敛**：client 经内部 bridge 网络用 DNS 名 `http://server:8080` 访问 server，不写死 IP、不依赖宿主机端口映射；仅 server 对宿主暴露端口。
- **真实的健康检测**：server healthcheck 用镜像内自带 busybox `wget` 请求 `/health`；client `depends_on: condition: service_healthy`，server 不健康 client 不启动。
- **编译打包理解**：单 Dockerfile 多阶段构建（`golang:1.25-alpine` 编译 → `alpine:3.20` 运行），`-trimpath -ldflags="-s -w"` 精简静态二进制，镜像约 15MB，不含编译工具链。
- **运行权限收紧**：镜像内 `USER 10001:10001` 非 root；compose 层 `cap_drop: ALL`、`read_only: true` 只读根文件系统（`/tmp` 用 tmpfs）、`no-new-privileges`。
- **规则与代码解耦**：规则在独立 JSON 文件，compose 只读挂载 `./rules` 进容器，改规则无需重建镜像。
- **运维要素**：`restart: unless-stopped`（server 自愈）、json-file 日志限额（10m×3）、`.env` 环境变量管理、优雅停机（SIGTERM 后 10s 宽限）、panic 恢复中间件、请求体大小限制与读写超时。

## 项目结构

```
├── cmd/
│   ├── server/main.go        # server：POST /fingerprint、GET /health
│   └── client/main.go        # client：读JSON→POST→表格输出
├── internal/fingerprint/
│   ├── engine.go             # 规则引擎（规则文件加载、正则+端口降级识别）
│   └── engine_test.go        # 引擎单元测试
├── rules/rules.json          # 识别规则（与代码解耦）
├── samples/input.json        # 示例输入数据
├── Dockerfile                # 多阶段构建，产出 server/client 两个镜像
├── docker-compose.yml        # 一键编排 + 健康检测 + 权限收紧
├── .env.example              # 环境变量样例
└── go.mod                    # 仅标准库，无第三方依赖
```

## 假设与已知局限

1. 识别以 banner 为主、端口为辅：banner 未命中时对 `ports` 列表中的端口做低置信度（≤0.5）提示识别。
2. 输入中 `\xHH` 写法（扫描工具常见、非标准 JSON）由 client 转成标准 `\u00HH` 转义后解析；server 直接接收真实字节，均支持二进制 banner。
3. Redis banner 不含版本号，`version` 固定为空，confidence 0.7（与示例一致）。
4. 批量接口校验策略：字段缺失/非法返回 400 并指出第几条；banner 无法识别不算错误，返回 unknown。
5. 状态无持久化需求（识别服务本身无状态），持久化点为挂载卷：规则目录 `rules/` 与样例数据目录 `samples/`。
6. 当前规则覆盖题目要求的 5 类协议及常见变体；未见过的协议返回 `unknown`，可通过规则文件扩展。
7. 注意：TCP 协议均以 "220" 开头（如 SMTP），本系统 FTP 规则只匹配带具体产品名的 banner，避免误报；未识别的 220 响应按端口提示或 unknown 处理。
