from datetime import datetime

timestamp_ms = 1742901170418
date_pub = datetime.fromtimestamp(timestamp_ms / 1000)

print(date_pub)
