# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      apt-transport-https curl ca-certificates gnupg && \
    curl -s https://packagecloud.io/install/repositories/varnishcache/varnish76/script.deb.sh | bash && \
    apt-get install -y --no-install-recommends \
      varnish varnish-dev \
      g++-14-riscv64-linux-gnu \
      clang-18 lld-18 \
      cmake ninja-build make \
      libssl-dev libjemalloc-dev \
      python3 pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build RISC-V ELF programs (basic + js; Rust is skipped)
SHELL ["/bin/bash", "-c"]
RUN cd program && \
    export GCC_TRIPLE=riscv64-linux-gnu && \
    source detect_compiler.sh && \
    mkdir -p $GCC_TRIPLE && \
    cd $GCC_TRIPLE && \
    cmake ../cpp \
      -DGCC_TRIPLE=$GCC_TRIPLE \
      -DCMAKE_TOOLCHAIN_FILE=micro/toolchain.cmake && \
    make -j$(nproc)

# Build the VMOD
RUN CC=clang-18 CXX=clang++-18 \
    cmake -S. -Bbuild -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DVARNISH_PLUS=OFF \
      -DRISCV_BINARY_TRANSLATION=OFF \
      -DPython3_EXECUTABLE=$(which python3) && \
    cmake --build build --config Release -j$(nproc)

# Capture the vmod install path for the runtime stage
RUN pkg-config --variable=vmoddir varnishapi > /vmoddir

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      apt-transport-https curl ca-certificates gnupg && \
    curl -s https://packagecloud.io/install/repositories/varnishcache/varnish76/script.deb.sh | bash && \
    apt-get install -y --no-install-recommends \
      varnish libssl3 libjemalloc2 && \
    rm -rf /var/lib/apt/lists/*

# Install the VMOD into the correct directory
COPY --from=builder /vmoddir /vmoddir
COPY --from=builder /src/build/libvmod_riscv.so /tmp/libvmod_riscv.so
RUN cp /tmp/libvmod_riscv.so "$(cat /vmoddir)"/ && \
    rm /tmp/libvmod_riscv.so /vmoddir

# Pre-built RISC-V ELF programs
COPY --from=builder /src/program/riscv64-linux-gnu/basic /opt/riscv-programs/basic
COPY --from=builder /src/program/riscv64-linux-gnu/js    /opt/riscv-programs/js

COPY demo/demo-docker.vcl /etc/varnish/demo.vcl

RUN mkdir -p /tmp/varnishd

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["varnishd", "-F", \
     "-f", "/etc/varnish/demo.vcl", \
     "-a", "0.0.0.0:8000", \
     "-p", "workspace_client=128k", \
     "-p", "thread_pool_stack=64k", \
     "-n", "/tmp/varnishd"]
