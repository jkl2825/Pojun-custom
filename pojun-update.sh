#!/usr/bin/env bash
# 一键更新：拉上游新镜像 -> 在其上重建「工具层」-> 改 .env -> 重启容器。
#
# 为什么不用 `docker compose pull && up`：上游镜像只有基础件（且不含 impacket），
# 直接换上游会把本机补的 65 件工具全丢掉。这里把工具层固化在 Dockerfile.tools 里，
# 上游出新版只重建这一层。
set -euo pipefail
cd "$(dirname "$0")"

# This checkout contains local application patches that Dockerfile.tools never builds.
# Refuse before pulling, editing .env or restarting a running experiment.
if [ -f "DEPLOY-本地部署说明.md" ] || [ -f server/escalation.go ]; then
  echo "This checkout contains local Pojun patches. Upstream tool-layer updates are disabled." >&2
  echo "Build the current source with embedui, validate against an isolated PostgreSQL database," >&2
  echo "then deploy the verified binary and pin the resulting local image. See the local deployment notes." >&2
  exit 2
fi

BASE="${POJUN_BASE_IMAGE:-xingchuan1314/pojun:latest}"
TAG="${POJUN_LOCAL_TAG:-tools-$(date +%Y%m%d-%H%M)}"
IMAGE="pojun-local/pojun"

echo "[1/4] 拉取上游基础镜像: $BASE"
docker pull "$BASE"

echo "[2/4] 重建工具层 -> $IMAGE:$TAG（apt/pip/GitHub Release，首次约 10~20 分钟）"
docker build -f Dockerfile.tools --build-arg BASE="$BASE" -t "$IMAGE:$TAG" .

echo "[3/4] 更新 .env 指向新镜像"
sed -i.bak -E "s|^POJUN_IMAGE=.*|POJUN_IMAGE=$IMAGE|; s|^POJUN_TAG=.*|POJUN_TAG=$TAG|" .env
grep -E '^POJUN_(IMAGE|TAG)=' .env

echo "[4/4] 重启容器（数据在 pgdata 卷与 ./data，不受影响）"
docker compose up -d

echo "完成。当前镜像: $IMAGE:$TAG"
echo "工具可用性核对："
docker compose exec pojun sh -c 'for b in nmap sqlmap httpx ffuf feroxbuster impacket evil-winrm netexec chisel ligolo-ng seclists nuclei; do printf "  %-14s" $b; command -v $b >/dev/null && echo OK || echo MISSING; done'
