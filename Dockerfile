# 先用这几个命令把镜像保存下来，就不用构建时下载了
# docker pull rust:1.90.0
# docker save -o rust_1.90.0.tar rust:1.90.0
# docker pull gcr.io/distroless/static-debian11
# docker save -o distroless_static_debian11.tar gcr.io/distroless/static-debian11

# 使用官方Rust镜像作为构建阶段
FROM --platform=linux/amd64 rust:1.90.0 AS builder
# 构建
WORKDIR /app
COPY Cargo.toml .
COPY src/ src
RUN cargo build --release

# 第二阶段：使用精简镜像运行
# FROM alpine:3.18
FROM --platform=linux/amd64 gcr.io/distroless/cc-debian12
WORKDIR /app
# 从musl target目录复制二进制文件
COPY --from=builder --chmod=755 /app/target/release/rust-bind ./app
EXPOSE 50002
CMD ["./app"]