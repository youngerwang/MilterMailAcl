import json

with open("db.json", mode="r", encoding="utf-8") as f:
    entries = json.load(f)

big_entries = []
for i in range(10000):
    big_entries.extend(entries)

with open("db_big.json", mode="w", encoding="utf-8") as f:
    json.dump(big_entries, f, indent=2)