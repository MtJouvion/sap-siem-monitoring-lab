import random
from datetime import datetime, timedelta

def generate_timestamp(start, i, interval_seconds=30):
    return (start + timedelta(seconds=i * interval_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

def choose_weighted(choices):
    items, weights = zip(*choices)
    return random.choices(items, weights=weights, k=1)[0]

def main():
    random.seed(42)

    total_events = 1000
    start_time = datetime(2025, 3, 1, 8, 0, 0)

    systems = ["SAPPRD", "SAPQAS"]
    clients = ["100", "200"]
    business_users = ["LSMITH", "JJONES", "AP_CLERK1", "AP_CLERK2", "AP_CLERK3", "MM_USER1"]
    admins = ["FI_ADMIN", "BASIS01", "SEC_ADMIN"]
    firefighter_ids = ["FF_FI_01", "FF_BASIS_01"]
    all_users = business_users + admins

    tcodes_normal = ["FB60", "FB65", "F110", "ME21N", "ME22N", "ME51N"]
    tcodes_admin = ["SU01", "PFCG", "SE38", "SM19"]
    vendor_ids = [f"V{1000+i}" for i in range(200)]

    src_ips_corp = [f"10.10.{sub}.{host}" for sub in range(1, 4) for host in range(10, 30)]
    src_ips_ext = ["203.0.113.57", "198.51.100.23", "192.0.2.45"]

    high_risk_roles = ["SAP_ALL", "FI_SUPER", "BASIS_ADMIN"]
    normal_roles = ["FI_CLERK", "FI_AP_USER", "MM_USER", "DISPLAY_ONLY"]

    event_types = [
        ("LOGIN_SUCCESS", 35),
        ("LOGIN_FAILED", 20),
        ("POST_DOCUMENT", 20),
        ("CHANGE_ROLE", 5),
        ("CREATE_VENDOR", 5),
        ("FIREFIGHTER_LOGIN", 2),
        ("FIREFIGHTER_LOGOUT", 2),
        ("DISPLAY_DOCUMENT", 11),
    ]

    lines = []

    # Helper to create a log line
    def make_line(ts, **fields):
        base = ts
        kvs = " ".join(f"{k}={v}" for k, v in fields.items())
        return f"{base} {kvs}"

    # Generate mostly normal background activity
    for i in range(total_events - 80):  # reserve some for explicit attack scenarios
        ts = generate_timestamp(start_time, i)
        system = random.choice(systems)
        client = random.choice(clients)
        event_type = choose_weighted(event_types)

        # default values
        user = random.choice(all_users)
        source_ip = random.choice(src_ips_corp)
        severity = "INFO"
        tcode = ""
        message = '"-"'
        extra_fields = {}

        if event_type in ("LOGIN_SUCCESS", "LOGIN_FAILED"):
            tcode = ""
            if event_type == "LOGIN_FAILED":
                severity = "WARN"
                if random.random() < 0.2:
                    source_ip = random.choice(src_ips_ext)
            message = f'"{event_type} for user {user}"'
        elif event_type == "POST_DOCUMENT":
            tcode = random.choice(["FB60", "FB65", "F110"])
            amount = round(random.uniform(100, 25000), 2)
            currency = "USD"
            vendor_id = random.choice(vendor_ids)
            extra_fields.update({
                "amount": f"{amount:.2f}",
                "currency": currency,
                "vendor_id": vendor_id,
            })
            message = '"Vendor invoice posted"'
        elif event_type == "CHANGE_ROLE":
            tcode = "SU01"
            target_user = random.choice(business_users)
            new_role = random.choice(normal_roles)
            extra_fields.update({
                "target_user": target_user,
                "new_role": new_role,
            })
            message = f'"Role {new_role} assigned to user {target_user}"'
        elif event_type == "CREATE_VENDOR":
            tcode = "XK01"
            vendor_id = random.choice(vendor_ids)
            extra_fields.update({"vendor_id": vendor_id})
            message = '"Vendor created"'
        elif event_type in ("FIREFIGHTER_LOGIN", "FIREFIGHTER_LOGOUT"):
            user = random.choice(firefighter_ids)
            tcode = ""
            severity = "CRITICAL" if event_type == "FIREFIGHTER_LOGIN" else "INFO"
            message = f'"{event_type} for firefighter ID {user}"'
        elif event_type == "DISPLAY_DOCUMENT":
            tcode = random.choice(["FB03", "ME23N"])
            message = '"Document displayed"'

        line = make_line(
            ts,
            system=system,
            client=client,
            user=user,
            tcode=tcode,
            event_type=event_type,
            result="SUCCESS" if event_type != "LOGIN_FAILED" else "FAILURE",
            source_ip=source_ip,
            severity=severity,
            message=message,
            **extra_fields,
        )
        lines.append(line)

    # --- Explicit attack scenarios ---

    # 1) Brute-force from external IP leading to success
    attack_ip = random.choice(src_ips_ext)
    victim_user = random.choice(business_users)
    base_index = total_events - 80

    for j in range(15):
        ts = generate_timestamp(start_time, base_index + j)
        line = make_line(
            ts,
            system="SAPPRD",
            client="100",
            user=victim_user,
            tcode="",
            event_type="LOGIN_FAILED",
            result="FAILURE",
            source_ip=attack_ip,
            severity="WARN",
            message=f'"LOGIN_FAILED for user {victim_user} from external IP"',
        )
        lines.append(line)

    ts = generate_timestamp(start_time, base_index + 16)
    lines.append(make_line(
        ts,
        system="SAPPRD",
        client="100",
        user=victim_user,
        tcode="",
        event_type="LOGIN_SUCCESS",
        result="SUCCESS",
        source_ip=attack_ip,
        severity="INFO",
        message=f'"LOGIN_SUCCESS for user {victim_user} after multiple failures from same IP"',
    ))

    # 2) Privilege escalation - high risk role assignment
    ts = generate_timestamp(start_time, base_index + 20)
    new_role = random.choice(high_risk_roles)
    lines.append(make_line(
        ts,
        system="SAPPRD",
        client="100",
        user="FI_ADMIN",
        tcode="SU01",
        event_type="CHANGE_ROLE",
        result="SUCCESS",
        source_ip="10.10.1.10",
        severity="CRITICAL",
        target_user=victim_user,
        new_role=new_role,
        message=f'"High-risk role {new_role} assigned to user {victim_user}"',
    ))

    # 3) High-value posting after escalation
    ts = generate_timestamp(start_time, base_index + 22)
    vendor_fraud_id = "V9999"
    lines.append(make_line(
        ts,
        system="SAPPRD",
        client="100",
        user=victim_user,
        tcode="FB60",
        event_type="POST_DOCUMENT",
        result="SUCCESS",
        source_ip=attack_ip,
        severity="CRITICAL",
        amount="250000.00",
        currency="USD",
        vendor_id=vendor_fraud_id,
        message='"High-value vendor invoice posted"',
    ))

    # 4) Vendor creation + posting in short window (fraud chain)
    fraud_user = random.choice(business_users)
    ts = generate_timestamp(start_time, base_index + 30)
    lines.append(make_line(
        ts,
        system="SAPPRD",
        client="100",
        user=fraud_user,
        tcode="XK01",
        event_type="CREATE_VENDOR",
        result="SUCCESS",
        source_ip="10.10.2.15",
        severity="INFO",
        vendor_id=vendor_fraud_id,
        message='"Suspicious vendor created shortly before large posting"',
    ))

    ts = generate_timestamp(start_time, base_index + 32)
    lines.append(make_line(
        ts,
        system="SAPPRD",
        client="100",
        user=fraud_user,
        tcode="FB60",
        event_type="POST_DOCUMENT",
        result="SUCCESS",
        source_ip="10.10.2.15",
        severity="CRITICAL",
        amount="175000.00",
        currency="USD",
        vendor_id=vendor_fraud_id,
        message='"Large invoice posted to newly created vendor"',
    ))

    # 5) Firefighter abuse off-hours
    ts = (start_time + timedelta(days=1, hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ff_user = firefighter_ids[0]
    lines.append(make_line(
        ts,
        system="SAPPRD",
        client="100",
        user=ff_user,
        tcode="",
        event_type="FIREFIGHTER_LOGIN",
        result="SUCCESS",
        source_ip="10.10.3.50",
        severity="CRITICAL",
        message='"FIREFIGHTER_LOGIN during off-hours"',
    ))
    ts2 = (start_time + timedelta(days=1, hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines.append(make_line(
        ts2,
        system="SAPPRD",
        client="100",
        user=ff_user,
        tcode="",
        event_type="FIREFIGHTER_LOGOUT",
        result="SUCCESS",
        source_ip="10.10.3.50",
        severity="INFO",
        message='"FIREFIGHTER_LOGOUT after off-hours activity"',
    ))

    # Shuffle to simulate some randomness in ordering, but keep relative proximity
    random.shuffle(lines)

    with open("sap_audit.log", "w") as f:
        for line in lines:
            f.write(line + "\n")

if __name__ == "__main__":
    main()
