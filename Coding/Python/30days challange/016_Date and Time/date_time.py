

# Python datetime
# Python has date and time module to handle date and time
import datetime
print(dir(datetime))

from datetime import datetime
now = datetime.now()
print(f"Todays date is: {now}")

year = now.year
month = now.month
day = now.day
hour = now.hour
min = now.minute
second = now.second
timestamp = now.timestamp()
print(year, month, day, hour, min, second, timestamp)

print(f"{year}/{month}/{day} {hour}:{min}")

# Formating the datetime using the strftime() 

now = now.strftime("%d/%m%Y, %H:%M:%S")
print(now)