import csv
import argparse
from datetime import datetime

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


if __name__ == "__main__":
    main()
