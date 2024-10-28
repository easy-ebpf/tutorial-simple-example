# From official php image.
FROM golang:alpine

LABEL org.opencontainers.image.source="https://github.com/easy-ebpf/tutorial-simple-example"

RUN mkdir -p /workspace/cli

# Install quality-of-life packages.
RUN apk --update add --no-cache curl git vim fish tmux neovim wget make

RUN \
    # Install persistent / runtime deps
    apk --update add --no-cache clang llvm bcc bcc-tools gcompat libbpf-dev linux-headers bpftool libbpf

# Make fish the default shell
RUN sed -i 's|/bin/sh$|/usr/bin/fish|' /etc/passwd

# Prevent container from exiting early.
CMD ["sleep", "infinity"]
