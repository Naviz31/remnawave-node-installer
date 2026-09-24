import ipaddress
from dataclasses import dataclass, field
from typing import List

from .constants import COVER_PORT, NODE_PORT
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
        if result.returncode == 0 and result.stdout.strip():
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
        ["ufw", "allow", f"{ssh_port}/tcp", "comment", "remnawave-node ssh"],
        ["ufw", "allow", "80/tcp", "comment", "remnawave-node http"],
        ["ufw", "allow", "443/tcp", "comment", "remnawave-node https"],
    ])
    for ip in ips:
        plan.commands.append(["ufw", "allow", "from", ip, "to", "any", "port", str(node_port), "proto", "tcp", "comment", "remnawave-node panel"])
        plan.identifiers.append(f"ufw:{ip}:{node_port}")
    if not ips:
        plan.warnings.append("PANEL_IPS не задан: NODE_PORT останется закрыт, пока вы не добавите IP панели")
    plan.identifiers.extend([f"ufw:base:{ssh_port}", "ufw:base:80", "ufw:base:443"])
    return plan


def build_nft_plan(panel_ips: List[str], ssh_port: int, node_port: int = NODE_PORT) -> FirewallPlan:
    ips = _validate_panel_ips(panel_ips)
    plan = FirewallPlan("nftables")
    table = "remnawave_node"
    commands = [["nft", "add", "table", "inet", table], ["nft", "add", "chain", "inet", table, "input", "{", "type", "filter", "hook", "input", "priority", "-5", ";", "policy", "accept", ";", "}"]]
    commands.extend([
        ["nft", "add", "rule", "inet", table, "input", "ct", "state", "established,related", "accept"],
        ["nft", "add", "rule", "inet", table, "input", "iif", "lo", "accept"],
        ["nft", "add", "rule", "inet", table, "input", "tcp", "dport", str(ssh_port), "accept"],
        ["nft", "add", "rule", "inet", table, "input", "tcp", "dport", "{", "80,443", "}", "accept"],
    ])
    for ip in ips:
        family = "ip6" if ":" in ip else "ip"
        commands.append(["nft", "add", "rule", "inet", table, "input", family, "saddr", ip, "tcp", "dport", str(node_port), "accept"])
    commands.extend([
        ["nft", "add", "rule", "inet", table, "input", "tcp", "dport", str(node_port), "drop"],
        ["nft", "add", "rule", "inet", table, "input", "tcp", "dport", str(COVER_PORT), "drop"],
    ])
    plan.commands = commands
    plan.identifiers = [f"nft:{table}"]
    if not ips:
        plan.warnings.append("PANEL_IPS не задан: NODE_PORT останется закрыт, пока вы не добавите IP панели")
    return plan


def build_iptables_plan(panel_ips: List[str], ssh_port: int, node_port: int = NODE_PORT) -> FirewallPlan:
    ips = _validate_panel_ips(panel_ips)
    chain = "REMNAWAVE_NODE"
    plan = FirewallPlan("iptables")
    plan.commands = [["iptables", "-N", chain], ["iptables", "-I", "INPUT", "1", "-j", chain]]
    plan.commands.extend([
        ["iptables", "-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["iptables", "-A", chain, "-i", "lo", "-j", "ACCEPT"],
        ["iptables", "-A", chain, "-p", "tcp", "--dport", str(ssh_port), "-j", "ACCEPT"],
        ["iptables", "-A", chain, "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "ACCEPT"],
    ])
    for ip in ips:
        plan.commands.append(["iptables", "-A", chain, "-p", "tcp", "-s", ip, "--dport", str(node_port), "-j", "ACCEPT"])
    plan.commands.extend([
        ["iptables", "-A", chain, "-p", "tcp", "--dport", str(node_port), "-j", "DROP"],
        ["iptables", "-A", chain, "-p", "tcp", "--dport", str(COVER_PORT), "-j", "DROP"],
    ])
    plan.identifiers = [f"iptables:{chain}"]
    if not ips:
        plan.warnings.append("PANEL_IPS не задан: NODE_PORT останется закрыт, пока вы не добавите IP панели")
    return plan


def apply_plan(plan: FirewallPlan, runner: CommandRunner) -> List[str]:
    if plan.backend == "none":
        return []
    if plan.backend == "ufw":
        current = runner.run(["ufw", "status"], check=False, timeout=15).stdout
        created = []
        for command in plan.commands:
            port = next((token.split("/", 1)[0] for token in command if "/tcp" in token), "")
            source = command[command.index("from") + 1] if "from" in command else ""
            already_present = bool(port and port in current and (not source or source in current))
            if not already_present:
                runner.run(command, timeout=30)
                created.append(f"ufw:{source}:{port}" if source else f"ufw:base:{port}")
        return created
    for command in plan.commands:
        runner.run(command, timeout=30)
    return list(plan.identifiers)


def remove_managed_firewall(identifiers: List[str], runner: CommandRunner) -> None:
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
        elif identifier.startswith("ufw:"):
            _, kind, value = identifier.split(":", 2)
            if kind == "base":
                runner.run(["ufw", "delete", "allow", f"{value}/tcp"], check=False, timeout=30)
            elif kind and value:
                runner.run(["ufw", "delete", "allow", "from", kind, "to", "any", "port", value, "proto", "tcp"], check=False, timeout=30)
