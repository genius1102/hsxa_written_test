# banner-fingerprint 镜像：一个 Dockerfile 产出 server/client 两个精简运行镜像。
# 多阶段构建：builder 阶段编译 → 运行阶段仅保留静态二进制 + 必要 CA 证书，非 root 运行。

# ---------- 构建阶段 ----------
FROM golang:1.25-alpine AS builder
WORKDIR /src
# 仅标准库依赖；先复制 go.mod 以充分利用 Docker 构建缓存
COPY go.mod ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
# COMPONENT = server | client，对应 cmd/ 下的入口目录（compose 通过 build.args 传入）
ARG COMPONENT
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${COMPONENT}

# ---------- server 运行阶段 ----------
FROM alpine:3.20 AS server
# busybox 自带 addgroup/adduser/wget；服务间为内网明文 HTTP，无需 CA 证书包（不依赖外部软件源，构建更稳）
RUN addgroup -g 10001 app \
    && adduser -D -u 10001 -G app app
COPY --from=builder /out/app /usr/local/bin/bannerf-server
# 默认规则内置于镜像；compose 中用只读卷挂载 ./rules 覆盖，实现规则与代码解耦
COPY rules/rules.json /etc/bannerf/rules.json
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["bannerf-server"]

# ---------- client 运行阶段 ----------
FROM alpine:3.20 AS client
# busybox 自带 addgroup/adduser；client 走内网明文 HTTP，无需 CA 证书包
RUN addgroup -g 10001 app \
    && adduser -D -u 10001 -G app app
COPY --from=builder /out/app /usr/local/bin/bannerf-client
USER 10001:10001
ENTRYPOINT ["bannerf-client"]
