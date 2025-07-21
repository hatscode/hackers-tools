# web scrapping

# Web scraping is the process of extracting and collecting data from websites and storing it on a local machine or in a database.


import requests
from bs4 import BeautifulSoup
url = 'https://google.com'

# Lets use the requests get method to fetch the data from url

response = requests.get(url)
# lets check the status
status = response.status_code
print(status) # 200 means the fetching was successful

