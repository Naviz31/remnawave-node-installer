import ipaddress
import re
import socket
from typing import List, Optional, Tuple


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
    try:
        records = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return [], []
    for family, _, _, _, sockaddr in records:
        if family == socket.AF_INET:
            ipv4.add(sockaddr[0])
        elif family == socket.AF_INET6:
            ipv6.add(sockaddr[0])
    return sorted(ipv4), sorted(ipv6)


def domain_points_to(domain: str, public_ipv4: Optional[str], public_ipv6: Optional[str] = None) -> Tuple[bool, str]:
    ipv4, ipv6 = resolve_domain(domain)
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
