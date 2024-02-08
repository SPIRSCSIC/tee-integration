import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sess = requests.Session()

sess.verify = False
sess.cert = ("./user.crt", "./user.key")
# sess.cert = ("./test.crt", "./test.key")

res = sess.get("https://localhost:5000/")
print(res, res.text)
