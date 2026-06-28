import csv
import argparse
from datetime import datetime
import math

def load_auth_events(path):
    events = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("ts") or not row.get("user"):
                continue
            events.append(row)
    return events


def load_ground_truth(path):
    labels = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("ts") or not row.get("user") or not row.get("label"):
                continue
            labels.append(row)
    return labels

def haversine(lat1, lon1, lat2, lon2):
    R = 6371  # Earth radius in km
    phi1 = math.radians(float(lat1))
    phi2 = math.radians(float(lat2))
    dphi = math.radians(float(lat2) - float(lat1))
    dlambda = math.radians(float(lon2) - float(lon1))

    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    return R * c

def detect_impossible_travel(events, threshold_kmh=900):
    alerts = []

    # Group events by user
    users = {}
    for e in events:
        if e["result"] != "success":
            continue  # only successful logins matter
        users.setdefault(e["user"], []).append(e)

    # Process each user separately
    for user, evs in users.items():
        # Sort by timestamp
        evs.sort(key=lambda x: x["ts"])

        # Compare each event to the previous one
        for i in range(1, len(evs)):
            prev = evs[i-1]
            curr = evs[i]

            # Parse timestamps
            t1 = datetime.fromisoformat(prev["ts"])
            t2 = datetime.fromisoformat(curr["ts"])
            minutes = (t2 - t1).total_seconds() / 60.0
            if minutes <= 0:
                continue

            # Compute distance
            dist = haversine(prev["lat"], prev["lon"], curr["lat"], curr["lon"])

            # Compute speed
            hours = minutes / 60.0
            speed = dist / hours

            # Check threshold
            if speed > threshold_kmh:
                alerts.append({
                    "detector": "impossible_travel",
                    "user": user,
                    "ts": curr["ts"],
                    "prev_city": prev["city"],
                    "curr_city": curr["city"],
                    "gap_min": round(minutes),
                    "dist_km": round(dist),
                    "speed_kmh": round(speed)
                })

    return alerts
def detect_off_hours_admin(events, start_hour=8, end_hour=18, service_account="svc_nightly"):
    alerts = []

    for e in events:
        # Only care about admin role
        if e["role"] != "admin":
            continue

        # Skip the legitimate nightly service account
        if e["user"] == service_account:
            continue

        # Parse timestamp
        try:
            ts = datetime.fromisoformat(e["ts"])
        except:
            continue

        hour = ts.hour

        # Check if outside business hours
        if hour < start_hour or hour >= end_hour:
            alerts.append({
                "detector": "off_hours_admin",
                "user": e["user"],
                "ts": e["ts"],
                "city": e["city"],
                "country": e["country"],
                "hour": hour
            })

    return alerts

def detect_bruteforce(events, fail_threshold=10, spray_threshold=5):
    alerts = []

    # Count failures per user (store full events)
    user_failures = {}
    # Count failures per IP (store full events)
    ip_failures = {}

    for e in events:
        if e["result"] != "failure":
            continue

        user = e["user"]
        ip = e["src_ip"]

        # Store full event objects, not integers
        user_failures.setdefault(user, [])
        user_failures[user].append(e)

        ip_failures.setdefault(ip, [])
        ip_failures[ip].append(e)

    # Pattern A: brute force (many failures on one account)
    for user, ev_list in user_failures.items():
        if len(ev_list) >= fail_threshold:
            last_event = ev_list[-1]
            alerts.append({
                "detector": "bruteforce",
                "user": user,
                "ts": last_event["ts"],
                "src_ip": last_event["src_ip"],
                "fail_count": len(ev_list)
            })

    # Pattern B: password spray (one IP failing on many accounts)
    for ip, ev_list in ip_failures.items():
        unique_users = set(e["user"] for e in ev_list)
        if len(unique_users) >= spray_threshold:
            last_event = ev_list[-1]
            alerts.append({
                "detector": "password_spray",
                "user": last_event["user"],
                "ts": last_event["ts"],
                "src_ip": ip,
                "user_count": len(unique_users)
            })

    return alerts



def detect_privilege_escalation(events):
    alerts = []

    # Track each user's roles over time
    user_roles = {}

    for e in events:
        user = e["user"]
        role = e["role"]

        # Initialize role history
        if user not in user_roles:
            user_roles[user] = set()

        # Add this role to the user's history
        user_roles[user].add(role)

        # If this event is admin but user never had admin before → escalation
        if role == "admin" and len(user_roles[user]) > 1:
            alerts.append({
                "detector": "privilege_escalation",
                "user": user,
                "ts": e["ts"],
                "city": e["city"],
                "country": e["country"],
                "roles_seen": list(user_roles[user])
            })

    return alerts


def score_alerts(alerts, truth):
    # Convert truth list into a set of (ts, user) pairs
    truth_set = set()
    for t in truth:
        truth_set.add((t["ts"], t["user"]))

    # Convert alerts list into a set of (ts, user) pairs
    alert_set = set()
    for a in alerts:
        alert_set.add((a["ts"], a["user"]))

    # True positives: alert matches truth
    tp = alert_set & truth_set

    # False positives: alert not in truth
    fp = alert_set - truth_set

    # False negatives: truth not alerted
    fn = truth_set - alert_set

    # Precision and recall
    precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) > 0 else 0
    recall = len(tp) / (len(tp) + len(fn)) if (len(tp) + len(fn)) > 0 else 0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("auth_path", help="Path to auth_events.csv")
    parser.add_argument("--truth", dest="truth_path", help="Path to ground_truth.csv")
    args = parser.parse_args()


    events = load_auth_events(args.auth_path)
    print(f"Loaded {len(events)} auth events")

    if args.truth_path:
        labels = load_ground_truth(args.truth_path)
        print(f"Loaded {len(labels)} ground-truth labels")
    else:
        labels = []


    impossible_alerts = detect_impossible_travel(events, threshold_kmh=900)
    print(f"Impossible travel alerts: {len(impossible_alerts)}")

    off_hours_alerts = detect_off_hours_admin(events, start_hour=8, end_hour=18)
    print(f"Off-hours admin alerts: {len(off_hours_alerts)}")
    brute_alerts = detect_bruteforce(events, fail_threshold=10, spray_threshold=5)
    print(f"Brute-force / spray alerts: {len(brute_alerts)}")
    priv_alerts = detect_privilege_escalation(events)
    print(f"Privilege escalation alerts: {len(priv_alerts)}")


    all_alerts = (
        impossible_alerts +
        off_hours_alerts +
        brute_alerts +
        priv_alerts
    )

    results = score_alerts(all_alerts, labels)

    print("\n=== SCORING ===")
    print(f"True positives: {len(results['tp'])}")
    print(f"False positives: {len(results['fp'])}")
    print(f"False negatives: {len(results['fn'])}")
    print(f"Precision: {results['precision']:.2f}")
    print(f"Recall: {results['recall']:.2f}")



if __name__ == "__main__":
    main()
