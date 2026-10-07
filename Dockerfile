# 使用轻量且现代的 Debian 基础镜像
FROM debian:bookworm-slim

# 设置非交互式安装，避免安装过程中卡住
ENV DEBIAN_FRONTEND=noninteractive

# 安装运行所需的系统依赖（包括网络工具、证书以及 subconverter 运行所需的动态库）
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    tar \
    ca-certificates \
    libpcre3 \
    libyaml-cpp0.7 \
    libcurl4 \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 下载并解压 subconverter 预编译压缩包
# （此处以 tindy2013/subconverter v0.7.2 为例，如果你用的是 MetaCubeX 分支的 release 压缩包链接，可以自行替换下方 URL）
RUN wget -O subconverter.tar.gz https://github.com/tindy2013/subconverter/releases/download/v0.7.2/subconverter_linux64.tar.gz \
    && tar -zxvf subconverter.tar.gz \
    && rm subconverter.tar.gz

# 暴露 subconverter 的默认端口
EXPOSE 25500

# 启动 subconverter
WORKDIR /app/subconverter
CMD ["./subconverter"]
