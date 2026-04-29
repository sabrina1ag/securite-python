"""Traffic and security analysis primitives."""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network

from scapy.all import ARP, DNS, DNSRR, ICMP, IP, TCP, UDP, Ether, Packet, Raw

LOGGER = logging.getLogger(__name__)

SQLI_PATTERNS = [
    r"'[\s]*OR",
    r"UNION[\s]+SELECT",
    r"DROP[\s]+TABLE",
    r"--",
    r"xp_",
]
SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)
EXPECTED_DNS_NETWORKS = [ip_network("10.0.0.0/8"), ip_network("192.168.0.0/16")]


@dataclass(slots=True)
class AttackEvent:
    """Represent one detected security attack.

    Attributes:
        attack_type: Name of attack.
        protocol: Concerned protocol.
        source_ip: Attacker source IP when available.
        source_mac: Attacker source MAC when available.
        timestamp: UTC timestamp in ISO format.
        occurrences: Number of occurrences observed so far.
    """

    attack_type: str
    protocol: str
    source_ip: str
    source_mac: str
    timestamp: str
    occurrences: int = 1


@dataclass(slots=True)
class AnalysisResult:
    """Aggregate analysis outputs for reporting."""

    protocol_counts: dict[str, int]
    attacks: list[AttackEvent]

    @property
    def total_packets(self) -> int:
        """Return total analyzed packets."""
        return sum(self.protocol_counts.values())


class TrafficAnalyzer:
    """Analyze packets and detect suspicious activity."""

    def __init__(self) -> None:
        """Initialize analyzer state stores."""
        self.protocol_counts: Counter[str] = Counter()
        self._attacks: dict[tuple[str, str, str], AttackEvent] = {}
        self._arp_ip_to_macs: dict[str, set[str]] = defaultdict(set)
        self._syn_windows: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._syn_per_second: dict[str, deque[float]] = defaultdict(deque)

    def analyze_packets(self, packets: Iterable[Packet]) -> AnalysisResult:
        """Analyze packets and produce detection results.

        Args:
            packets: Iterable of Scapy packets.

        Returns:
            Structured protocol counters and attack events.
        """
        for packet in packets:
            self._count_protocols(packet)
            self._detect_arp_spoofing(packet)
            self._detect_sql_injection(packet)
            self._detect_port_scanning(packet)
            self._detect_dns_spoofing(packet)
            self._detect_syn_flood(packet)

        return AnalysisResult(
            protocol_counts=dict(self.protocol_counts),
            attacks=list(self._attacks.values()),
        )

    def _record_attack(
        self, attack_type: str, protocol: str, source_ip: str, source_mac: str
    ) -> None:
        """Create or increment an attack event.

        Args:
            attack_type: Attack label.
            protocol: Related protocol.
            source_ip: Source IP.
            source_mac: Source MAC.
        """
        key = (attack_type, source_ip, source_mac)
        if key not in self._attacks:
            self._attacks[key] = AttackEvent(
                attack_type=attack_type,
                protocol=protocol,
                source_ip=source_ip,
                source_mac=source_mac,
                timestamp=datetime.now(UTC).isoformat(),
                occurrences=1,
            )
            LOGGER.warning("Attaque detectee: %s depuis %s", attack_type, source_ip)
        else:
            self._attacks[key].occurrences += 1

    def _count_protocols(self, packet: Packet) -> None:
        """Count known protocol layers in packet."""
        if packet.haslayer(Ether):
            self.protocol_counts["Ethernet"] += 1
        if packet.haslayer(ARP):
            self.protocol_counts["ARP"] += 1
        if packet.haslayer(IP):
            self.protocol_counts["IP"] += 1
        if packet.haslayer(TCP):
            self.protocol_counts["TCP"] += 1
        if packet.haslayer(UDP):
            self.protocol_counts["UDP"] += 1
        if packet.haslayer(DNS):
            self.protocol_counts["DNS"] += 1
        if packet.haslayer(ICMP):
            self.protocol_counts["ICMP"] += 1
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore").upper()
            if "HTTP/" in payload or "GET " in payload or "POST " in payload:
                self.protocol_counts["HTTP"] += 1

    def _detect_arp_spoofing(self, packet: Packet) -> None:
        """Detect ARP spoofing based on multiple MACs per ARP source IP."""
        if not packet.haslayer(ARP):
            return
        arp_layer = packet[ARP]
        if int(arp_layer.op) != 2:
            return
        source_ip = str(arp_layer.psrc)
        source_mac = str(arp_layer.hwsrc)
        macs = self._arp_ip_to_macs[source_ip]
        macs.add(source_mac)
        if len(macs) > 1:
            self._record_attack("ARP Spoofing", "ARP", source_ip, source_mac)

    def _detect_sql_injection(self, packet: Packet) -> None:
        """Detect SQL injection patterns inside TCP payload."""
        if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            return
        payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore")
        if not SQLI_REGEX.search(payload):
            return
        source_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
        source_mac = packet[Ether].src if packet.haslayer(Ether) else "unknown"
        self._record_attack("Injection SQL", "TCP/HTTP", source_ip, source_mac)

    def _detect_port_scanning(self, packet: Packet) -> None:
        """Detect scans from many SYN probes to distinct ports in 5 seconds."""
        if not (packet.haslayer(TCP) and packet.haslayer(IP)):
            return
        tcp_layer = packet[TCP]
        if not tcp_layer.flags.S or tcp_layer.flags.A:
            return
        source_ip = str(packet[IP].src)
        source_mac = packet[Ether].src if packet.haslayer(Ether) else "unknown"
        timestamp = float(getattr(packet, "time", 0.0))
        dest_port = int(tcp_layer.dport)
        window = self._syn_windows[source_ip]
        window.append((timestamp, dest_port))
        while window and timestamp - window[0][0] > 5:
            window.popleft()
        unique_ports = {entry[1] for entry in window}
        if len(unique_ports) > 15:
            self._record_attack("Port Scanning", "TCP", source_ip, source_mac)

    def _detect_dns_spoofing(self, packet: Packet) -> None:
        """Detect suspicious DNS responses with abnormal TTL or IP range."""
        if not packet.haslayer(DNS):
            return
        dns = packet[DNS]
        if int(dns.qr) != 1 or int(dns.ancount) <= 0:
            return
        source_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
        source_mac = packet[Ether].src if packet.haslayer(Ether) else "unknown"
        answers = dns.an if isinstance(dns.an, list) else [dns.an]
        for answer in answers:
            if not isinstance(answer, DNSRR):
                continue
            if answer.type != 1:
                continue
            rdata = str(answer.rdata)
            ttl = int(answer.ttl)
            invalid_range = not self._is_expected_dns_ip(rdata)
            if ttl == 0 or invalid_range:
                self._record_attack("DNS Spoofing", "DNS", source_ip, source_mac)
                break

    def _detect_syn_flood(self, packet: Packet) -> None:
        """Detect SYN flood from same source over one second."""
        if not (packet.haslayer(TCP) and packet.haslayer(IP)):
            return
        tcp_layer = packet[TCP]
        if not tcp_layer.flags.S or tcp_layer.flags.A:
            return
        source_ip = str(packet[IP].src)
        source_mac = packet[Ether].src if packet.haslayer(Ether) else "unknown"
        timestamp = float(getattr(packet, "time", 0.0))
        timeline = self._syn_per_second[source_ip]
        timeline.append(timestamp)
        while timeline and timestamp - timeline[0] > 1:
            timeline.popleft()
        if len(timeline) > 100:
            self._record_attack("SYN Flood / DDoS", "TCP", source_ip, source_mac)

    def _is_expected_dns_ip(self, value: str) -> bool:
        """Check whether DNS answer is in expected private ranges."""
        try:
            addr = ip_address(value)
        except ValueError:
            return False
        return any(addr in network for network in EXPECTED_DNS_NETWORKS)
