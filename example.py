from napalm import get_network_driver

hostname = "**hostname**"
username = "admin"
password = "***password***"
secret = "***enable_password***"
 
driver = get_network_driver("cisco_wlc")
device_detail = {
    "hostname": hostname,
    "username": username,
    "password": password,
    "optional_args": {
        "secret": secret
    }
}

with driver(**device_detail) as router:
    print(router.get_config())
