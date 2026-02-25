import csv
from collections import Counter

in_path = "data/sysmon_eid3.csv"
top_out = "outputs/top_destinations.csv"
timeline_out = "outputs/timeline.csv"

counts = Counter()
timeline_rows = 0
total = 0

with open(in_path, newline="", encoding="utf-8-sig") as f:
    reader = csv.DictReader(f)

    # Write timeline as we read (keeps it simple and fast)
    with open(timeline_out, "w", newline="", encoding="utf-8") as tf:
        tw = csv.writer(tf)
        tw.writerow(["_time", "host", "DestinationIp", "DestinationPort"])

        for row in reader:
            total += 1
            t = (row.get("_time") or "").strip()
            host = (row.get("host") or "").strip()
            ip = (row.get("DestinationIp") or "").strip()
            port = (row.get("DestinationPort") or "").strip()

            # write timeline row only if key fields exist
            if t and host and ip and port:
                tw.writerow([t, host, ip, port])
                timeline_rows += 1
                counts[(ip, port)] += 1

print(f"Rows parsed: {total}")
print(f"Timeline rows written: {timeline_rows}")

print("\nTop destinations (IP:Port):")
for (ip, port), c in counts.most_common(10):
    print(f"  {ip}:{port}  -> {c}")

with open(top_out, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["DestinationIp", "DestinationPort", "Count"])
    for (ip, port), c in counts.most_common(10):
        w.writerow([ip, port, c])

print(f"\nWrote: {timeline_out}")
print(f"Wrote: {top_out}")
