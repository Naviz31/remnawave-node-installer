import json
import ipaddress
import re
import socket
from typing import List, Optional, Tuple

from .errors import InstallerError


DOMAIN_RE = re.compile(r"^(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\Z")


def normalize_domain(raw: str) -> str:
    value = raw.strip().lower().rstrip(".")
    if "://" in value or "/" in value or any(char.isspace() for char in value):
        raise ValueError("домен должен быть без схемы, пути и пробелов")
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("домен содержит недопустимые символы") from exc
    if not DOMAIN_RE.fullmatch(ascii_value):
        raise ValueError("ожидался FQDN, например node.example.com")
    return ascii_value


def parse_ips(raw: str) -> List[str]:
    result = []
    for item in raw.replace(",", " ").split():
        try:
            address = ipaddress.ip_address(item)
        except ValueError as exc:
            raise ValueError(f"недопустимый IP-адрес: {item}") from exc
        if str(address) not in result:
            result.append(str(address))
    return result


def resolve_domain(domain: str) -> Tuple[List[str], List[str]]:
    ipv4 = set()
    ipv6 = set()
    fqdn = domain.rstrip(".") + "."
    try:
        records = socket.getaddrinfo(fqdn, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return [], []
    for family, _, _, _, sockaddr in records:
        if family == socket.AF_INET:
            ipv4.add(sockaddr[0])
        elif family == socket.AF_INET6:
            ipv6.add(sockaddr[0])
    return sorted(ipv4), sorted(ipv6)


def _resolve_public_dns(domain: str, runner, record_type: int) -> List[str]:
    if runner is None:
        return []
    encoded_domain = domain.rstrip(".")
    addresses = set()
    for endpoint in ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"):
        url = f"{endpoint}?name={encoded_domain}&type={record_type}"
        try:
            result = runner.run(
                ["curl", "-fsS", "--max-time", "5", "-H", "accept: application/dns-json", url],
                check=False,
                timeout=8,
            )
            payload = json.loads(result.stdout) if result.returncode == 0 else {}
        except (InstallerError, TypeError, ValueError, json.JSONDecodeError):
            continue
        for answer in payload.get("Answer", []):
            if answer.get("type") != record_type:
                continue
            try:
                address = ipaddress.ip_address(answer.get("data", ""))
            except ValueError:
                continue
            addresses.add(str(address))
    return sorted(addresses)


def domain_points_to(domain: str, public_ipv4: Optional[str], public_ipv6: Optional[str] = None, runner=None) -> Tuple[bool, str]:
    ipv4, ipv6 = resolve_domain(domain)
    ipv4 = sorted(set(ipv4) | set(_resolve_public_dns(domain, runner, 1)))
    ipv6 = sorted(set(ipv6) | set(_resolve_public_dns(domain, runner, 28)))
    if public_ipv4 and ipv4 and public_ipv4 not in ipv4:
        return False, f"A-запись не совпадает: ожидается {public_ipv4}, получено {', '.join(ipv4)}"
    if public_ipv4 and not ipv4:
        return False, "A-запись не найдена"
    if ipv6 and public_ipv6 and public_ipv6 not in ipv6:
        return False, f"AAAA-запись не совпадает: ожидается {public_ipv6}, получено {', '.join(ipv6)}"
    if ipv6 and not public_ipv6:
        return False, "обнаружена AAAA-запись, но публичный IPv6 этого сервера не определён"
    return True, "DNS указывает на сервер"


def valid_port(port: int) -> bool:
    return 1 <= port <= 65535
