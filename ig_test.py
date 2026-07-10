import requests
import re

url = "https://www.instagram.com/cristiano/"
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
}
r = requests.get(url, headers=headers)
print("Status:", r.status_code)
desc = re.findall(r'<meta property="og:description" content="(.*?)"', r.text)
img = re.findall(r'<meta property="og:image" content="(.*?)"', r.text)
print("Desc:", desc)
print("Image:", img)
