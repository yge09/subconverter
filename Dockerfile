# 阶段一：使用 Ubuntu 编译环境进行源码编译
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# 安装编译所需的依赖工具链和开发库
RUN apt-get update && apt-get install -y \
    g++ \
    cmake \
    git \
    libcurl4-openssl-dev \
    libpcre2-dev \
    rapidjson-dev \
    libyaml-cpp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 将你当前仓库（已包含 VLESS 逻辑）的所有源码复制到容器中
COPY . /app

# 编译源码
RUN mkdir build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release .. \
    && make -j$(nproc)

# 阶段二：精简的运行环境镜像
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# 安装运行所需的动态库
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libpcre3 \
    libyaml-cpp0.7 \
    libcurl4 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 从编译阶段仅把编译好的主程序和基础配置文件复制过来
COPY --from=builder /app/build/subconverter /app/subconverter/subconverter
COPY --from=builder /app/base /app/base

# 暴露默认端口
EXPOSE 25500

WORKDIR /app/subconverter
CMD ["./subconverter"]
