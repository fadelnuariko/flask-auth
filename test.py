import requests

url = 'http://localhost:5000/protected'
cookies = {'access_token_cookie': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY4MDAxNjY2NiwianRpIjoiMDdmYzBkYzctYjZhMy00YTI1LThkZjUtMjc5NDlhY2QyMTA3IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MSwibmJmIjoxNjgwMDE2NjY2LCJleHAiOjE2ODAwMTc1NjZ9.CmghWSxsAJCgTdhackb3YhSfZsz9QBS_-hfTx7l92Uw'}
headers = {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY4MDAxNjY2NiwianRpIjoiMDdmYzBkYzctYjZhMy00YTI1LThkZjUtMjc5NDlhY2QyMTA3IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MSwibmJmIjoxNjgwMDE2NjY2LCJleHAiOjE2ODAwMTc1NjZ9.CmghWSxsAJCgTdhackb3YhSfZsz9QBS_-hfTx7l92Uw'}
response = requests.get(url, cookies=cookies,  headers=headers)
print(response.json())
