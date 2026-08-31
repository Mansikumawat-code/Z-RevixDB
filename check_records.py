import sqlite3

conn = sqlite3.connect('zrevixdb.sqlite3')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

cursor.execute('SELECT id, collection, key FROM records LIMIT 5')
records = cursor.fetchall()
print('Available records:')
for r in records:
    print(f'  - {r["collection"]}/{r["key"]} (ID: {r["id"]})')

conn.close()
