#!/usr/bin/env bash
# gather_jq.sh — 시스템 정보/패키지 수집(JSON Pretty) — Bash + jq
set -euo pipefail

has() { command -v "$1" >/dev/null 2>&1; }

# jq 확인 및 안내
if ! has jq; then
  echo "[오류] jq 명령어를 찾을 수 없습니다: jq: command not found" >&2
  echo "해결 방법:" >&2
  echo "  1) jq 설치 후 다시 실행" >&2
  echo "     - RHEL/CentOS/Rocky: sudo dnf install -y jq  또는 sudo yum install -y jq" >&2
  echo "     - Ubuntu/Debian:     sudo apt-get update && sudo apt-get install -y jq" >&2
  echo "     - Alpine:            sudo apk add jq" >&2
  echo "  2) jq 설치가 불가한 환경이면 Python 버전 스크립트를 실행하세요." >&2
  echo "     - 예: chmod +x gather_py.py && ./gather_py.py  (또는 python3 gather_py.py)" >&2
  exit 127
fi

HOST="$(hostname 2>/dev/null || echo unknown)"
DATE_STR="$(date +%Y%m%d 2>/dev/null || echo 00000000)"
OUT_FILE="${HOST}_${DATE_STR}.json"

get_os_string() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    printf '%s %s' "${NAME:-Unknown}" "${VERSION_ID:-}"
  elif [ -f /etc/redhat-release ]; then
    head -1 /etc/redhat-release
  else
    uname -srm 2>/dev/null || echo ""
  fi
}

OS_OUT="$(get_os_string 2>/dev/null || echo "")"
KERNEL_OUT="$(uname -r 2>/dev/null || echo "")"
UPTIME_OUT="$(uptime 2>/dev/null || echo "")"
BOOT_OUT="$( (uptime -s 2>/dev/null || who -b 2>/dev/null || echo "") | tr -d '\n' )"

collect_packages() {
  if has rpm; then
    rpm -qa 2>/dev/null
  elif has dpkg-query; then
    dpkg-query -W -f='${Package}-${Version}\n' 2>/dev/null
  elif has apk; then
    apk info -vv 2>/dev/null
  else
    :
  fi
}

# 패키지 목록 -> 중복 제거, 빈 줄 제거 후 JSON 배열
PKGS_JSON="$(
  collect_packages | sort -u | awk 'NF' | jq -R -s 'split("\n") | map(select(length>0))'
)"
[ -n "${PKGS_JSON:-}" ] || PKGS_JSON='[]'

# pretty 형식으로 출력(-S: key 정렬은 하지 않음, 기본 2-space indent)
jq -n \
  --arg title "호스트 정보" \
  --arg host "$HOST" \
  --arg os_value "$OS_OUT" \
  --arg kernel_value "$KERNEL_OUT" \
  --arg uptime_value "$UPTIME_OUT" \
  --arg boot_value "$BOOT_OUT" \
  --argjson pkgs "$PKGS_JSON" \
'{
  title: $title,
  host: $host,
  data: {
    "OS Version": $os_value,
    "Kernel version": $kernel_value,
    "uptime": $uptime_value,
    "Boot time": $boot_value,
    "Install Packages": $pkgs
  }
}' > "$OUT_FILE"

echo "$OUT_FILE 생성 완료 (pretty JSON)"