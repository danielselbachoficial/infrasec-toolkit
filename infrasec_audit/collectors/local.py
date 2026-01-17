from __future__ import annotations

import json
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path

from infrasec_audit.models import Artifacts, BinaryInfo, PackageInfo, ServiceInfo, SystemInfo


def _run_command(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    output = result.stdout.strip() or result.stderr.strip()
    return output


def _parse_os_release() -> tuple[str, str | None]:
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        return platform.system(), None
    data = {}
    for line in os_release.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            data[key] = value.strip().strip('"')
    return data.get("NAME", platform.system()), data.get("VERSION_ID")


def _detect_package_manager() -> str:
    if shutil.which("dpkg"):
        return "dpkg"
    if shutil.which("rpm"):
        return "rpm"
    if shutil.which("pacman"):
        return "pacman"
    return "unknown"


def _collect_packages(manager: str) -> list[PackageInfo]:
    packages: list[PackageInfo] = []
    if manager == "dpkg":
        output = _run_command(["dpkg", "-l"])
        for line in output.splitlines():
            if line.startswith("ii"):
                parts = re.split(r"\s+", line)
                if len(parts) >= 3:
                    packages.append(PackageInfo(name=parts[1], version=parts[2], manager=manager))
    elif manager == "rpm":
        output = _run_command(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"])
        for line in output.splitlines():
            if not line.strip():
                continue
            name, _, version = line.partition(" ")
            packages.append(PackageInfo(name=name, version=version.strip(), manager=manager))
    elif manager == "pacman":
        output = _run_command(["pacman", "-Q"])
        for line in output.splitlines():
            if not line.strip():
                continue
            name, _, version = line.partition(" ")
            packages.append(PackageInfo(name=name, version=version.strip(), manager=manager))
    return packages


def _collect_services() -> list[ServiceInfo]:
    output = ""
    if shutil.which("ss"):
        output = _run_command(["ss", "-tulpn"])
    elif shutil.which("netstat"):
        output = _run_command(["netstat", "-tulpn"])

    services: list[ServiceInfo] = []
    for line in output.splitlines():
        if not line or line.startswith("Netid") or line.startswith("Active"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 5:
            continue
        protocol = parts[0]
        local_address = parts[4]
        process = parts[-1] if parts[-1] != "-" else None
        port = None
        if ":" in local_address:
            port_part = local_address.rsplit(":", 1)[-1]
            if port_part.isdigit():
                port = int(port_part)
        services.append(
            ServiceInfo(
                name=process or protocol,
                protocol=protocol,
                local_address=local_address,
                port=port,
                process=process,
            )
        )
    return services


def _binary_version(binary: str, args: list[str]) -> BinaryInfo | None:
    path = shutil.which(binary)
    if not path:
        return None
    output = _run_command([path, *args])
    version = output.splitlines()[0] if output else None
    return BinaryInfo(name=binary, version=version, path=path)


def collect_local_artifacts() -> Artifacts:
    hostname = socket.gethostname()
    os_name, os_version = _parse_os_release()
    kernel = platform.release()
    system = SystemInfo(hostname=hostname, os_name=os_name, os_version=os_version, kernel=kernel)

    manager = _detect_package_manager()
    packages = _collect_packages(manager)
    services = _collect_services()
    binaries = []
    for binary, args in [
        ("openssl", ["version"]),
        ("nginx", ["-v"]),
        ("apache2", ["-v"]),
        ("httpd", ["-v"]),
        ("sshd", ["-V"]),
    ]:
        info = _binary_version(binary, args)
        if info:
            binaries.append(info)

    return Artifacts(system=system, packages=packages, services=services, binaries=binaries)


def artifacts_to_json(artifacts: Artifacts, output_path: Path) -> None:
    output_path.write_text(artifacts.model_dump_json(indent=2), encoding="utf-8")


def load_artifacts(path: Path) -> Artifacts:
    data = json.loads(path.read_text(encoding="utf-8"))
    return Artifacts.model_validate(data)
