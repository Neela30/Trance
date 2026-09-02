import sqlite3

conn = sqlite3.connect(
    "file:/home/sahe/tor-transfer/module-b/places.sqlite?mode=ro",
    uri=True
)
cur = conn.cursor()

cur.execute("SELECT * FROM moz_historyvisits LIMIT 20;")
rows = cur.fetchall()
print(f"Row count: {len(rows)}")
for row in rows:
    print(row)

cur.execute("SELECT url FROM moz_places WHERE url LIKE '%xm3raaijein%';")
print(cur.fetchall())
conn.close()