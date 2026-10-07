FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

ARG NODE_VERSION=22
ARG TERRAFORM_VERSION=1.13.4

USER root

# --------------------------------------------------
# Remove stale Yarn APT repository from base image
# --------------------------------------------------

RUN find /etc/apt/sources.list.d /etc/apt \
        -type f \
        -exec grep -Il "dl.yarnpkg.com" {} \; \
        -exec sed -i '/dl\.yarnpkg\.com/d' {} + \
    && rm -f /etc/apt/sources.list.d/yarn.list \
    && rm -f /etc/apt/sources.list.d/yarn.sources

# --------------------------------------------------
# Basic utilities
# --------------------------------------------------

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        unzip \
        ca-certificates \
        gnupg \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------
# Node.js 22
# --------------------------------------------------

RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && node --version \
    && npm --version \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------
# Terraform
# --------------------------------------------------

RUN curl -fsSL \
        "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" \
        -o /tmp/terraform.zip \
    && unzip -q /tmp/terraform.zip -d /usr/local/bin \
    && rm -f /tmp/terraform.zip \
    && terraform version

# --------------------------------------------------
# AWS CLI v2
# --------------------------------------------------

RUN curl -fsSL \
        "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" \
        -o /tmp/awscliv2.zip \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/aws /tmp/awscliv2.zip \
    && aws --version

# --------------------------------------------------
# Development user
# --------------------------------------------------

USER vscode
