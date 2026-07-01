import csv                          #Used to read CSV files
import argparse                     #Used to handle command-line arguments
from datetime import datetime       #Used to parse timestamps
import math                         #Used for haversine distance calculations

#Load authentication events from CSV
def load_auth_events(path):
    events = []   # List to store all valid events
    with open(path, newline="", encoding="utf-8") as f:    #Open CSV file safely
        reader = csv.DictReader(f)                         #Read rows as dictionaries
        for row in reader:                                 #Loop through each row
            if not row.get("ts") or not row.get("user"):   #Skip rows missing required fields
                continue
            events.append(row)                            #Add valid row to events list
    return events                                         #Return all loaded events

#Load ground-truth labels from CSV
def load_ground_truth(path):
    labels = []                 #List to store ground-truth attack labels
    with open(path, newline="", encoding="utf-8") as f:    #Open CSV file
        reader = csv.DictReader(f)                         #Read rows as dictionarie
        for row in reader:
             #Skip rows missing required fields
            if not row.get("ts") or not row.get("user") or not row.get("label"):
                continue
            labels.append(row)                     #Add valid label
    return labels                                  #Return all labels

#Calculate geographic distance using haversine formula
def haversine(lat1, lon1, lat2, lon2):
    R = 6371  # Earth radius in km

    #Convert coordinates to radians
    phi1 = math.radians(float(lat1))
    phi2 = math.radians(float(lat2))
    dphi = math.radians(float(lat2) - float(lat1))
    dlambda = math.radians(float(lon2) - float(lon1))

    #Apply haversine formula

    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    return R * c                    #Return distance in kilometers
    
#Detect impossible travel between consecutive successful logins
def detect_impossible_travel(events, threshold_kmh=900):
    alerts = []                 #Store impossible-travel alerts

    # Group events by user
    users = {}
    for e in events:
        if e["result"] != "success":                 #Only successful logins matter
            continue  # only successful logins matter
        users.setdefault(e["user"], []).append(e)     #Add event to user's list

    # Process each user separately
    for user, evs in users.items():
        # Sort by timestamp
        evs.sort(key=lambda x: x["ts"])            #Sort events by timestamp

        #Compare each event to the previous one
        for i in range(1, len(evs)):               #Previous login
            prev = evs[i-1]                        #Current login
            curr = evs[i]

            #Parse timestamps
            t1 = datetime.fromisoformat(prev["ts"])
            t2 = datetime.fromisoformat(curr["ts"])
            minutes = (t2 - t1).total_seconds() / 60.0   #Time difference in minutes
            if minutes <= 0:                             #Ignore invalid time gaps
                continue

            #Compute distance and speed
            dist = haversine(prev["lat"], prev["lon"], curr["lat"], curr["lon"])
            hours = minutes / 60.0
            speed = dist / hours

            #Check threshold
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
 
#Detect admin activity outside normal business hours   
def detect_off_hours_admin(events, start_hour=8, end_hour=18, service_account="svc_nightly"):
    alerts = []              #Store off-hours alerts

    for e in events:
        # Only care about admin role  
        if e["role"] != "admin":
            continue

        # Skip the legitimate nightly service account
        if e["user"] == service_account:
            continue

        # Parse timestamp
        try:
            ts = datetime.fromisoformat(e["ts"])    #Parse timestamp
        except:
            continue

        hour = ts.hour               #Extract hour of login

        #Check if outside business hours
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
#Detect brute-force and password-spray attacks
def detect_bruteforce(events, fail_threshold=10, spray_threshold=5):
    alerts = []

    # Count failures per user (store full events)
    user_failures = {}                              
    # Count failures per IP (store full events)
    ip_failures = {}                 

    for e in events:
        if e["result"] != "failure":             #Only failed logins matter
            continue

        user = e["user"]
        ip = e["src_ip"]

        #Store full event objects, not integers
        user_failures.setdefault(user, [])
        user_failures[user].append(e)

        ip_failures.setdefault(ip, [])
        ip_failures[ip].append(e)

    #Pattern A: brute force (many failures on one account)
    for user, ev_list in user_failures.items():
        if len(ev_list) >= fail_threshold:            #Too many failures on one user
            last_event = ev_list[-1]                  #Use last event timestamp
            alerts.append({
                "detector": "bruteforce",
                "user": user,
                "ts": last_event["ts"],
                "src_ip": last_event["src_ip"],
                "fail_count": len(ev_list)
            })

    #Pattern B: password spray (one IP failing on many accounts)
    for ip, ev_list in ip_failures.items():
        unique_users = set(e["user"] for e in ev_list)   #Count unique users
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



#Score alerts against ground truth using precision and recall
def score_alerts(alerts, truth):                              #Convert truth to set
    #Convert truth list into a set of (ts, user) pairs       
    truth_set = set()
    for t in truth:
        truth_set.add((t["ts"], t["user"]))

    #Convert alerts list into a set of (ts, user) pairs
    alert_set = set()
    for a in alerts:
        alert_set.add((a["ts"], a["user"]))

    #True positives: alert matches truth
    tp = alert_set & truth_set

    #False positives: alert not in truth
    fp = alert_set - truth_set

    #False negatives: truth not alerted
    fn = truth_set - alert_set

    #Precision and recall
    precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) > 0 else 0
    recall = len(tp) / (len(tp) + len(fn)) if (len(tp) + len(fn)) > 0 else 0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall
    }

#Main program: load data, run detectors, score results
def main():
    parser = argparse.ArgumentParser()      #Create argument parser
    parser.add_argument("auth_path", help="Path to auth_events.csv")   #Required file
    parser.add_argument("--truth", dest="truth_path", help="Path to ground_truth.csv")    #Optional file
    args = parser.parse_args()      #Parse arguments


    #Load authentication events
    events = load_auth_events(args.auth_path)        
    print(f"Loaded {len(events)} auth events")

    # Load ground truth if provided
    if args.truth_path:
        labels = load_ground_truth(args.truth_path)
        print(f"Loaded {len(labels)} ground-truth labels")
    else:
        labels = []

     
     #Run all detectors
    impossible_alerts = detect_impossible_travel(events, threshold_kmh=900)
    print(f"Impossible travel alerts: {len(impossible_alerts)}")

    off_hours_alerts = detect_off_hours_admin(events, start_hour=8, end_hour=18)
    print(f"Off-hours admin alerts: {len(off_hours_alerts)}")
    brute_alerts = detect_bruteforce(events, fail_threshold=10, spray_threshold=5)
    print(f"Brute-force / spray alerts: {len(brute_alerts)}")
   
    #Combine all alerts
    all_alerts = (
        impossible_alerts +
        off_hours_alerts +
        brute_alerts 
    )

    #score alerts
    results = score_alerts(all_alerts, labels)

    #Print scoring results
    print("\n=== SCORING ===")
    print(f"True positives: {len(results['tp'])}")
    print(f"False positives: {len(results['fp'])}")
    print(f"False negatives: {len(results['fn'])}")
    print(f"Precision: {results['precision']:.2f}")
    print(f"Recall: {results['recall']:.2f}")


#Run main() when script is executed
if __name__ == "__main__":
    main()
