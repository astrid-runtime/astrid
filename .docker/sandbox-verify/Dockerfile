FROM ubuntu:24.04

# Build deps + bubblewrap. The version of `bubblewrap` shipped with
# Ubuntu 24.04 is what the bug report cites — install it explicitly so
# the verification matches the reported environment.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        build-essential \
        pkg-config \
        libssl-dev \
        bubblewrap \
 && rm -rf /var/lib/apt/lists/*

# Use the official rustup installer pinned to a stable toolchain so the
# build is reproducible across runs.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH=/root/.cargo/bin:$PATH

# Source is bind-mounted at /src by the runner script so we don't pay
# the COPY-then-rebuild cost on every invocation.
WORKDIR /src
ENV CARGO_TARGET_DIR=/target

CMD ["bash"]
