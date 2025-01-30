import requests
import vulners



# url = 'http://vulners.com/api/v3/search/lucene'
# data = {
#     "query": "Cisco",
#     "apiKey": api_key  # Replace <Your-API-Key-Here> with actual API key
# }

# response = requests.post(url, json=data)
# assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
# print(response)


vulners_api = vulners.Vulners(api_key="Y5SPDSPWWSNNIC3A88QG26U0WSXTZR4TJ07598P673IHEV5AF8XUKG0Q5ZMM0O5C")
report = vulners_api.vulnslist_report(filter={"agentip": "10.2.2.2"})
print (report)
