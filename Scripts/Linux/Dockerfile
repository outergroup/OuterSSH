FROM ubuntu:24.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates clang cmake gcc gdb git libclang-rt-18-dev libssl-dev ninja-build \
    openssh-client openssh-server patch python3 zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

ENV CC=clang CXX=clang++
WORKDIR /workspace
