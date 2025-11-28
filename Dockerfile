# syntax=docker/dockerfile:1
FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG PRIVATEER_VERSION=v0.13.2

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    jq \
    python3 \
    python3-pip \
    make \
    git \
    awscli \
    gnupg \
    software-properties-common \
    lsb-release \
    golang \
  && rm -rf /var/lib/apt/lists/*

# Install Terraform from HashiCorp apt repo
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list && \
    apt-get update && apt-get install -y --no-install-recommends terraform && \
    rm -rf /var/lib/apt/lists/*

# Python tooling
RUN python3 -m pip install --no-cache-dir --upgrade pip prowler

ENV PATH="/root/.local/bin:/root/.privateer/bin:${PATH}"
ENV GOTOOLCHAIN=auto

WORKDIR /workspace
COPY . .

# Privateer CLI (prefer local artifacts after COPY)
RUN if [ -x ./privateer ]; then \
      install -m 0755 ./privateer /usr/local/bin/privateer; \
    elif [ -f ./privateer_Linux_x86_64.tar.gz ]; then \
      tar -xzf ./privateer_Linux_x86_64.tar.gz -C /usr/local/bin privateer; \
    else \
      curl -L -o /tmp/privateer.tar.gz https://github.com/privateercloud/privateer/releases/download/${PRIVATEER_VERSION}/privateer_Linux_x86_64.tar.gz && \
      tar -xzf /tmp/privateer.tar.gz -C /usr/local/bin privateer && \
      rm /tmp/privateer.tar.gz; \
    fi

RUN chmod +x validate-prequisites.sh checks/*.sh scripts/*.sh

# Build and install the generated Privateer plugin if present
# Install prebuilt plugin if present (skip building from source to avoid Go toolchain constraints)
RUN mkdir -p /root/.privateer/bin && \
    if [ -f plugins/plugin-ccc-vpc/vpc ]; then \
      install -m 0755 plugins/plugin-ccc-vpc/vpc /root/.privateer/bin/vpc; \
    else \
      echo "Plugin binary not found at plugins/plugin-ccc-vpc/vpc; skipping installation."; \
    fi

CMD ["bash"]
