import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .constants import NODE_PORT
from .system import CommandRunner


@dataclass
class FirewallPlan:
    backend: str
    commands: List[List[str]] = field(default_factory=list)
    identifiers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def detect_backend(runner: CommandRunner) -> str:
    if runner.exists("ufw"):
        status = runner.run(["ufw", "status"], check=False, timeout=15)
        if "Status: active" in status.stdout:
            return "ufw"
    if runner.exists("nft"):
        result = runner.run(["nft", "list", "ruleset"], check=False, timeout=15)
        if result.returncode == 0 and result.stdout.strip() and find_nft_input_chain(runner):
            return "nftables"
    if runner.exists("iptables"):
        return "iptables"
    return "none"


def _validate_panel_ips(panel_ips: List[str]) -> List[str]:
    values = []
    for value in panel_ips:
        ipaddress.ip_address(value)
        if value not in values:
            values.append(value)
    return values


def build_ufw_plan(panel_ips: List[str], ssh_port: int, node_port: int = NODE_PORT) -> FirewallPlan:
    ips = _validate_panel_ips(panel_ips)
    plan = FirewallPlan("ufw")
    plan.commands.extend([
        ["ufw", "allow", "80/tcp", "comment", "remnawave-node http"],
        ["ufw", "allow", "443/tcp", "comment", "remnawave-node https"],
    ])
    for ip in ips:
        plan.commands.append(["ufw", "allow", "from", ip, "to", "any", "port", str(node_port), "proto", "tcp", "comment", "remnawave-node panel"])
        plan.identifiers.append(f"ufw:{ip}:{node_port}")
    if not ips:
        plan.warnings.append("PANEL_IPS не задан: NODE_PORT останется закрыт, пока вы не добавите IP панели")
    plan.identifiers.extend(["ufw:base:80", "ufw:base:443"])
    return plan


def find_nft_input_chain(runner: CommandRunner) -> Optional[Tuple[str, str, str]]:
    """Find an existing inet input base chain to avoid changing its policy."""
    result = runner.run(["nft", "-j", "list", "ruleset"], check=False, timeout=15)
    if result.returncode != 0:
        return None
    try:
        for item in json.loads(result.stdout).get("nftables", []):
            chain = item.get("chain", {})
            if chain.get("family") == "inet" and chain.get("hook") == "input":
                return chain["family"], chain["table"], chain["name"]
    except (KeyError, TypeError, ValueError):
        return None
    return None


def build_nft_plan(panel_ips: List[str], ssh_port: int, node_port: int = NODE_PORT, input_chain=None) -> FirewallPlan:
    ips = _validate_panel_ips(panel_ips)
    plan = FirewallPlan("nftables")
    chain = "remnawave_node_api"
    if input_chain:
        family, table, parent = input_chain
        commands = [["nft", "add", "chain", family, table, chain]]
    else:
        family, table, parent = "inet", "remnawave_node", "input"
        commands = [
            ["nft", "add", "table", family, table],
            ["nft", "add", "chain", family, table, parent, "{", "type", "filter", "hook", "input", "priority", "-5", ";", "policy", "accept", ";", "}"],
            ["nft", "add", "chain", family, table, chain],
        ]
    for ip in ips:
        address_family = "ip6" if ":" in ip else "ip"
        commands.append(["nft", "add", "rule", family, table, chain, address_family, "saddr", ip, "tcp", "dport", str(node_port), "accept"])
    commands.extend([
        ["nft", "add", "rule", family, table, chain, "tcp", "dport", str(node_port), "drop"],
        ["nft", "add", "rule", family, table, chain, "return"],
        ["nft", "insert", "rule", family, table, parent, "tcp", "dport", str(node_port), "jump", chain],
    ])
    plan.commands = commands
    plan.identifiers = [f"nft:{family}:{table}:{parent}:{chain}:{node_port}"]
    if not ips:
        plan.warnings.append("PANEL_IPS не задан: NODE_PORT останется закрыт, пока вы не добавите IP панели")
    return plan


def build_iptables_plan(panel_ips: List[str], ssh_port: int, node_port: int = NODE_PORT) -> FirewallPlan:
    """Create narrowly scoped IPv4 and IPv6 INPUT jumps for Node API only."""
    ips = _validate_panel_ips(panel_ips)
    plan = FirewallPlan("iptables")
    plan.commands = []
    plan.identifiers = []
    for tool, chain, family_ips, identifier_prefix in (
        ("iptables", "REMNAWAVE_NODE", [ip for ip in ips if ":" not in ip], "iptables"),
        ("ip6tables", "REMNAWAVE_NODE6", [ip for ip in ips if ":" in ip], "ip6tables"),
    ):
        plan.commands.extend([
            [tool, "-N", chain],
            [tool, "-I", "INPUT", "1", "-p", "tcp", "--dport", str(node_port), "-j", chain],
        ])
        for ip in family_ips:
            plan.commands.append([tool, "-A", chain, "-p", "tcp", "-s", ip, "--dport", str(node_port), "-j", "ACCEPT"])
        plan.commands.extend([
            [tool, "-A", chain, "-p", "tcp", "--dport", str(node_port), "-j", "DROP"],
            [tool, "-A", chain, "-j", "RETURN"],
        ])
        plan.identifiers.append(f"{identifier_prefix}:{chain}:{node_port}")
    if not ips:
        plan.warnings.append("PANEL_IPS не задан: NODE_PORT останется закрыт, пока вы не добавите IP панели")
    return plan


def iptables_ipv6_available(runner: CommandRunner) -> bool:
    """Both families must be available before changing the iptables backend."""
    return runner.exists("iptables") and runner.exists("ip6tables")


def apply_plan(plan: FirewallPlan, runner: CommandRunner) -> List[str]:
    if plan.backend == "none":
        return []
    if plan.backend == "ufw":
        current = runner.run(["ufw", "status"], check=False, timeout=15).stdout
        created = []
        for command in plan.commands:
            if "from" in command and "port" in command:
                port = command[command.index("port") + 1]
            else:
                port = next((token.split("/", 1)[0] for token in command if "/tcp" in token), "")
            source = command[command.index("from") + 1] if "from" in command else ""
            already_present = _ufw_rule_present(current, port, source)
            if not already_present:
                runner.run(command, timeout=30)
                created.append(f"ufw:{source}:{port}" if source else f"ufw:base:{port}")
        return created
    for command in plan.commands:
        runner.run(command, timeout=30)
    return list(plan.identifiers)


def _ufw_rule_present(current: str, port: str, source: str) -> bool:
    if not port:
        return False
    expected = f"{port}/tcp"
    for raw_line in current.splitlines():
        line = " ".join(raw_line.split())
        if not line.startswith(expected + " ") or "ALLOW" not in line:
            continue
        if source:
            if source in line.split():
                return True
        elif "Anywhere" in line:
            return True
    return False


def _remove_nft_rule(family: str, table: str, parent: str, target_chain: str, node_port: str, runner: CommandRunner) -> None:
    rules = runner.run(["nft", "-a", "list", "chain", family, table, parent], check=False, timeout=30)
    for line in rules.stdout.splitlines():
        if f"dport {node_port}" in line and f"jump {target_chain}" in line:
            match = re.search(r"# handle (\d+)", line)
            if match:
                runner.run(["nft", "delete", "rule", family, table, parent, "handle", match.group(1)], check=False, timeout=30)
                break


def remove_managed_firewall(identifiers: List[str], runner: CommandRunner, node_port: int = NODE_PORT) -> None:
    for identifier in identifiers:
        if identifier == "nft:remnawave_node":
            runner.run(["nft", "delete", "table", "inet", "remnawave_node"], check=False, timeout=30)
        elif identifier == "iptables:REMNAWAVE_NODE":
            rules = runner.run(["iptables", "-S", "REMNAWAVE_NODE"], check=False, timeout=30)
            for line in reversed(rules.stdout.splitlines()):
                fields = line.split()
                if fields and fields[0] == "-A":
                    runner.run(["iptables", "-D", *fields[1:]], check=False, timeout=30)
            runner.run(["iptables", "-D", "INPUT", "-j", "REMNAWAVE_NODE"], check=False, timeout=30)
            runner.run(["iptables", "-X", "REMNAWAVE_NODE"], check=False, timeout=30)
        elif identifier.startswith("nft:"):
            _, family, table, parent, chain, rule_port = identifier.split(":", 5)
            _remove_nft_rule(family, table, parent, chain, rule_port, runner)
            runner.run(["nft", "delete", "chain", family, table, chain], check=False, timeout=30)
            if table == "remnawave_node":
                runner.run(["nft", "delete", "table", family, table], check=False, timeout=30)
        elif identifier.startswith("iptables:REMNAWAVE_NODE:"):
            tool = "iptables"
            _, chain, rule_port = identifier.split(":", 2)
            rules = runner.run([tool, "-S", chain], check=False, timeout=30)
            for line in reversed(rules.stdout.splitlines()):
                fields = line.split()
                if fields and fields[0] == "-A":
                    runner.run([tool, "-D", *fields[1:]], check=False, timeout=30)
            runner.run([tool, "-D", "INPUT", "-p", "tcp", "--dport", rule_port, "-j", chain], check=False, timeout=30)
            runner.run([tool, "-X", chain], check=False, timeout=30)
        elif identifier.startswith("ip6tables:REMNAWAVE_NODE6:"):
            tool = "ip6tables"
            _, chain, rule_port = identifier.split(":", 2)
            rules = runner.run([tool, "-S", chain], check=False, timeout=30)
            for line in reversed(rules.stdout.splitlines()):
                fields = line.split()
                if fields and fields[0] == "-A":
                    runner.run([tool, "-D", *fields[1:]], check=False, timeout=30)
            runner.run([tool, "-D", "INPUT", "-p", "tcp", "--dport", rule_port, "-j", chain], check=False, timeout=30)
            runner.run([tool, "-X", chain], check=False, timeout=30)
        elif identifier.startswith("ufw:"):
            _, kind, value = identifier.split(":", 2)
            if kind == "base":
                runner.run(["ufw", "delete", "allow", f"{value}/tcp"], check=False, timeout=30)
            elif kind:
                runner.run(["ufw", "delete", "allow", "from", kind, "to", "any", "port", value or str(node_port), "proto", "tcp"], check=False, timeout=30)
