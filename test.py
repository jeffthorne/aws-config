import json
from manager import Manager

dsm = Manager("awsconfig", "Password11!", "ACME Corp")

print dsm.does_aws_host_have_malware_turned_on("i-009476583069cf714").malware_protection_on