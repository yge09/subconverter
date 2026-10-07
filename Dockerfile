# 阶段一：构建环境 (以标准 C++ 项目为例，根据你的实际源码调整)
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y \
    g++ \
    cmake \
    git \
    libpcre3-dev \
    libyaml-cpp-dev \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# 假设通过 cmake 构建
RUN mkdir build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release .. \
    && make -j$(nproc)

# 阶段二：运行环境
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libpcre3 \
    libyaml-cpp0.7 \
    libcurl4 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# 从构建阶段复制编译好的二进制文件和必要配置文件
COPY --from=builder /build/build/subconverter /app/subconverter
COPY --from=builder /build/base /app/base

EXPOSE 25500
CMD ["./subconverter"]
