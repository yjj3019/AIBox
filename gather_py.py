#!/usr/bin/env python3
# gather_py.py — 시스템 정보/패키지 수집(JSON Pretty) — Python
import json, os, platform, socket, subprocess
from datetime import datetime

def sh(cmd: str) -> str:
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
        return out.decode(errors="replace").strip()
    except Exception:
        return ""

def has(cmd: str) -> bool:
    return subprocess.call(f"command -v {cmd} >/dev/null 2>&1", shell=True) == 0

def get_os_string() -> str:
    if os.path.exists("/etc/os-release"):
        data = {}
        with open("/etc/os-release", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    data[k] = v.strip().strip('"')
        name = data.get("NAME", "Unknown")
        ver = data.get("VERSION_ID", "")
        return f"{name} {ver}".strip()
    elif os.path.exists("/etc/redhat-release"):
        try:
            with open("/etc/redhat-release", "r", encoding="utf-8", errors="ignore") as f:
                return f.readline().strip()
        except Exception:
            return ""
    else:
        return f"{platform.system()} {platform.release()}"

def collect_packages():
    items = []
    if has("rpm"):
        out = sh("rpm -qa")
        items = out.splitlines()
    elif has("dpkg-query"):
        out = sh("dpkg-query -W -f='${Package}-${Version}\n'")
        items = out.splitlines()
    elif has("apk"):
        out = sh("apk info -vv")
        items = out.splitlines()
    cleaned = sorted({line.strip() for line in items if line and line.strip()})
    return cleaned

def main():
    host = socket.gethostname() or "unknown"
    date_str = datetime.now().strftime("%Y%m%d")
    out_file = f"{host}_{date_str}.json"

    os_ver = get_os_string()
    kernel_ver = sh("uname -r")
    uptime = sh("uptime")
    boot_time = sh("uptime -s") or sh("who -b")

    data = {
        "title": "호스트 정보",
        "host": host,
        "data": {
            "OS Version": os_ver,
            "Kernel version": kernel_ver,
            "uptime": uptime,
            "Boot time": boot_time,
            "Install Packages": collect_packages(),
        },
    }

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"{out_file} 생성 완료 (pretty JSON)")

if __name__ == "__main__":
    main()