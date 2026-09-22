from collections import defaultdict, deque
from datetime import datetime, timedelta
import time

from scapy.all import sniff, IP, TCP, UDP, ICMP

from database import get_connection
from risk_engine import record_network_risk

INTERFACE = "enp0s3"
PROTECTED_SERVER = "192.168.30.10"

ICMP_WINDOW_SECONDS = 10
ICMP_THRESHOLD = 20
TCP_WINDOW_SECONDS = 10
TCP_PORT_THRESHOLD = 5
UDP_WINDOW_SECONDS = 10
UDP_PORT_THRESHOLD = 5
ALERT_COOLDOWN_SECONDS = 15

ICMP_RISK = 65
TCP_SCAN_RISK = 50
UDP_SCAN_RISK = 45

icmp_events = defaultdict(deque)
tcp_events = defaultdict(deque)
udp_events = defaultdict(deque)
last_alert = {}


def now():
    return datetime.now()


def prune_times(queue, seconds):
    cutoff = now() - timedelta(seconds=seconds)
    while queue and queue[0] < cutoff:
        queue.popleft()


def prune_port_events(queue, seconds):
    cutoff = now() - timedelta(seconds=seconds)
    while queue and queue[0][0] < cutoff:
        queue.popleft()


def cooldown_ok(key):
    previous = last_alert.get(key)
    if previous is None:
        return True
    return (now() - previous).total_seconds() >= ALERT_COOLDOWN_SECONDS


def save_attack(attack_type, source_ip, protocol, risk_score, threat_level):
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO attack_logs
                (attack_type, source_ip, destination_ip,
                 protocol, risk_score, threat_level, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """,
            (
                attack_type,
                source_ip,
                PROTECTED_SERVER,
                protocol,
                risk_score,
                threat_level,
            ),
        )
        connection.commit()
    except Exception as error:
        print("[ATTACK LOG ERROR]", error)
    finally:
        try:
            if cursor is not None:
                cursor.close()
        finally:
            if connection is not None:
                connection.close()


def raise_network_alert(attack_type, source_ip, protocol, risk_score, threat_level):
    key = (attack_type, source_ip)
    if not cooldown_ok(key):
        return

    last_alert[key] = now()

    save_attack(
        attack_type=attack_type,
        source_ip=source_ip,
        protocol=protocol,
        risk_score=risk_score,
        threat_level=threat_level,
    )

    record_network_risk(
        source_ip=source_ip,
        risk_score=risk_score,
        attack_type=attack_type,
        threat_level=threat_level,
    )

    print(
        f"[DETECTED] {attack_type} | "
        f"source={source_ip} | target={PROTECTED_SERVER} | "
        f"risk={risk_score} | threat={threat_level}"
    )


def process_packet(packet):
    if IP not in packet:
        return

    ip = packet[IP]
    source_ip = ip.src
    destination_ip = ip.dst

    if destination_ip != PROTECTED_SERVER:
        return

    if ICMP in packet:
        queue = icmp_events[source_ip]
        queue.append(now())
        prune_times(queue, ICMP_WINDOW_SECONDS)

        if len(queue) >= ICMP_THRESHOLD:
            raise_network_alert(
                attack_type="ICMP Ping Flood",
                source_ip=source_ip,
                protocol="ICMP",
                risk_score=ICMP_RISK,
                threat_level="High",
            )
            queue.clear()

    if TCP in packet:
        tcp = packet[TCP]

        # Count initial SYN probes only; avoid counting normal established traffic.
        syn = bool(tcp.flags & 0x02)
        ack = bool(tcp.flags & 0x10)

        if syn and not ack:
            queue = tcp_events[source_ip]
            queue.append((now(), int(tcp.dport)))
            prune_port_events(queue, TCP_WINDOW_SECONDS)

            unique_ports = {port for _, port in queue}

            if len(unique_ports) >= TCP_PORT_THRESHOLD:
                raise_network_alert(
                    attack_type="TCP Port Scan",
                    source_ip=source_ip,
                    protocol="TCP",
                    risk_score=TCP_SCAN_RISK,
                    threat_level="Medium",
                )
                queue.clear()

    if UDP in packet:
        udp = packet[UDP]
        queue = udp_events[source_ip]
        queue.append((now(), int(udp.dport)))
        prune_port_events(queue, UDP_WINDOW_SECONDS)

        unique_ports = {port for _, port in queue}

        if len(unique_ports) >= UDP_PORT_THRESHOLD:
            raise_network_alert(
                attack_type="UDP Port Scan",
                source_ip=source_ip,
                protocol="UDP",
                risk_score=UDP_SCAN_RISK,
                threat_level="Medium",
            )
            queue.clear()


def main():
    print("=" * 68)
    print("ZTNA NETWORK THREAT ANALYZER")
    print("Interface:", INTERFACE)
    print("Protected server:", PROTECTED_SERVER)
    print("Important: network/source risk is kept separate from Employee/Guest identity risk.")
    print("=" * 68)

    while True:
        try:
            sniff(
                iface=INTERFACE,
                prn=process_packet,
                store=False,
                filter=f"host {PROTECTED_SERVER}",
            )
        except KeyboardInterrupt:
            print("\nAnalyzer stopped.")
            break
        except Exception as error:
            print("[SNIFF ERROR]", error)
            print("Retrying in 3 seconds...")
            time.sleep(3)


if __name__ == "__main__":
    main()
