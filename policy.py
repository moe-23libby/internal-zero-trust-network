BASE_DEVICES = {
    "192.168.56.10": {
        "device_name": "Employee-PC",
        "role": "employee",
        "base_score": 95
    },
    "192.168.56.20": {
        "device_name": "Guest-PC",
        "role": "guest",
        "base_score": 45
    },
    "192.168.56.30": {
        "device_name": "Kali-Attacker",
        "role": "attacker",
        "base_score": 10
    }
}

TRUST_THRESHOLD = 70

def get_risk_level(trust_score):
    if trust_score >= 80:
        return "Low"
    elif trust_score >= 50:
        return "Medium"
    elif trust_score >= 25:
        return "High"
    else:
        return "Critical"

def evaluate_device(ip_address, penalty=0):
    device = BASE_DEVICES.get(ip_address)

    if device is None:
        trust_score = 0
        return {
            "device_name": "Unknown-Device",
            "role": "unknown",
            "trust_score": trust_score,
            "risk_level": "Critical",
            "decision": "DENY",
            "reason": "Unknown device"
        }

    trust_score = max(0, device["base_score"] - penalty)
    risk_level = get_risk_level(trust_score)

    if trust_score >= TRUST_THRESHOLD:
        decision = "ALLOW"
        reason = "Trusted device"
    else:
        decision = "DENY"
        reason = "Low trust score or suspicious behavior"

    return {
        "device_name": device["device_name"],
        "role": device["role"],
        "trust_score": trust_score,
        "risk_level": risk_level,
        "decision": decision,
        "reason": reason
    }
