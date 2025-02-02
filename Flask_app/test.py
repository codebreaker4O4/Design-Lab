# Install the library if you haven't already
# pip install vulners

import vulners
from dotenv import load_dotenv
import os
load_dotenv()
# Initialize the API with your key
api_key = os.getenv("VULNERS_API_KEY")
vulners_api = vulners.Vulners(api_key=api_key)

# Now you can make the call
report = vulners_api.vulnslist_report(filter={"agentip": 10.3.100.100})
print(report)