# -*- coding: utf-8 -*-
# Copyright 2016 Dravetech AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for Skeleton.

Read https://napalm.readthedocs.io for more information.
"""

from napalm.base import NetworkDriver
from napalm.base.exceptions import (
    ConnectionException,
    SessionLockedException,
    MergeConfigException,
    ReplaceConfigException,
    CommandErrorException,
)
from napalm.base.utils import py23_compat
from napalm.base.netmiko_helpers import netmiko_args
import re
import copy


MINUTE_SECONDS = 60
HOUR_SECONDS = 60 * MINUTE_SECONDS
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS

class CiscoWlcDriver(NetworkDriver):
    """Napalm driver for Skeleton."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {}

        self.netmiko_optional_args = netmiko_args(optional_args)
        self.netmiko_optional_args.setdefault('port', 22)

        self.profile = ["cisco_wlc"]

    def open(self):
        """Open a connection to the device."""
        device_type = 'cisco_wlc_ssh'
        self.device = self._netmiko_open(
            device_type,
            netmiko_optional_args=self.netmiko_optional_args,
        )


    def close(self):
        """Close the connection to the device."""
        self._netmiko_close()

    def _send_command(self, command):
        """Wrapper for self.device.send.command().
        If command is a list will iterate through commands until valid command.
        """
        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd)
                    if "Incorrect usage" not in output:
                        break
            else:
                output = self.device.send_command(command)
            return self._send_command_postprocess(output)
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    @staticmethod
    def _send_command_postprocess(output):
        return output.strip()

    def is_alive(self):
        """Returns a flag with the state of the connection."""
        null = chr(0)
        if self.device is None:
            return {'is_alive': False}
        # SSH
        try:
            # Try sending ASCII null byte to maintain the connection alive
            self.device.write_channel(null)
            return {'is_alive': self.device.remote_conn.transport.is_active()}
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure that the connection is unusable
            return {'is_alive': False}
        return {'is_alive': False}


    def get_facts(self):
        """Return a set of facts from the devices."""
        # default values.
        vendor = u'Cisco'

        # obtain output from device
        show_sys_info = self._send_command('show sysinfo')
        show_inventory = self._send_command('show inventory')

        product_name = "Unknown"        # ex. Cisco Controller
        product_version = "Unknown"     # ex. 8.2.170.0
        hostname = "Unknown"            # ex. somehost
        management_ip = "Unknown"       # ex. 192.168.1.1
        configured_country = "Unknown"  # ex. BE - Belgium
        configured_wlans = "unknown"    # ex. 3
        active_clients = "unknown"      # ex. 3
        mac_address = "unknown"         # ex. 50:F7:22:0F:8D:20
        max_ap_supported = "unknown"    # ex. 50
        uptime = "Unknown"              # ex. 27 days 7 hrs 20 mins 28 secs
        chassis = "Unknown"             # ex. Cisco 2500 Series Wireless LAN Controller
        model = "Unknown"               # ex. AIR-CT2504-K9
        serial_number = "Unknown"

        for line in show_sys_info.splitlines():
            if 'Product Name' in line:
                product_name = line.split("..... ")[-1]

            if 'Product Version' in line:
                product_version = line.split("..... ")[-1]

            if 'System Name' in line:
                hostname = line.split("..... ")[-1]

            if 'IP Address' in line:
                management_ip = line.split("..... ")[-1]

            if 'System Up Time' in line:
                uptime = line.split("..... ")[-1]

            if 'Configured Country' in line:
                configured_country = line.split("..... ")[-1]

            if 'Number of WLANs' in line:
                configured_wlans = line.split("..... ")[-1]

            if 'Active Clients' in line:
                active_clients = line.split("..... ")[-1]

            if 'MAC Address' in line:
                mac_address = line.split("..... ")[-1]

            if 'Maximum number of APs supported' in line:
                max_ap_supported = line.split("..... ")[-1]


        # uptime/serial_number/IOS version
        for line in show_inventory.splitlines():
            if 'Chassis' in line:
                _, chassis = line.split('DESCR: ')
                chassis = chassis.replace('"', '')

            if 'PID:' in line:
                _, model = line.split("PID: ")
                model = model.split(",")[0]

            if 'SN: ' in line:
                _, serial_number = line.split("SN: ")

        return {
            'uptime': uptime,
            'vendor': vendor,
            'product_name': py23_compat.text_type(product_name),
            'serial_number': py23_compat.text_type(serial_number),
            'model': py23_compat.text_type(model),
            'hostname': py23_compat.text_type(hostname),
            'os_version': py23_compat.text_type(product_version),
            'management_ip': py23_compat.text_type(management_ip),
            'configured_country': py23_compat.text_type(configured_country),
            'configured_wlans': py23_compat.text_type(configured_wlans),
            'active_clients': py23_compat.text_type(active_clients),
            'mac_address': py23_compat.text_type(mac_address),
            'max_ap_supported': py23_compat.text_type(max_ap_supported),
            'uptime': py23_compat.text_type(uptime),
            'chassis': py23_compat.text_type(chassis)
        }


    @staticmethod
    def parse_uptime(uptime_str):
        """
        Extract the uptime string from the given Cisco IOS Device.
        Return the uptime in seconds as an integer

        Uptime format = 1 years 27 days 7 hrs 20 mins 28 secs
        """
        # Initialize to zero
        (years, weeks, days, hours, minutes, seconds) = (0, 0, 0, 0, 0, 0)

        uptime_str = uptime_str.strip()
        time_list = uptime_str.split(' ')
        # loop over list of tuples
        for element in zip(time_list[0::2], time_list[1::2]):
            if re.search("year", element[0]):
                years = int(element[1])
            elif re.search("week", element[0]):
                weeks = int(element[1])
            elif re.search("day", element[0]):
                days = int(element[1])
            elif re.search("(hour|hr)", element[0]):
                hours = int(element[1])
            elif re.search("min", element[0]):
                minutes = int(element[1])
            elif re.search("sec", element[0]):
                seconds = int(element[1])

        uptime_sec = (years * YEAR_SECONDS) + (weeks * WEEK_SECONDS) + (days * DAY_SECONDS) + \
                     (hours * HOUR_SECONDS) + (minutes * MINUTE_SECONDS) + seconds
        return uptime_sec


    def cli(self, commands):
        """
        Execute a list of commands and return the output in a dictionary format using the command
        as the key.
        Example input:
        ['show clock', 'show calendar']
        Output example:
        {   'show calendar': u'22:02:01 UTC Thu Feb 18 2016',
            'show clock': u'*22:01:51.165 UTC Thu Feb 18 2016'}
        """
        cli_output = dict()
        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            output = self._send_command(command)
            if 'Incorrect usage' in output:
                raise ValueError('Unable to execute command "{}"'.format(command))
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output


    def save_config(self):
        """
        Saves the config of the WLC, uses the paramiko save_config() function
        """
        output = self.device.save_config()
        return output


    def get_config(self, retrieve='all'):
        """Implementation of get_config for Cisco WLC.
        Returns the running configuration as dictionary.
        The keys of the dictionary represent the type of configuration
        (startup or running). The candidate is always empty string,
        since IOS does not support candidate configuration.
        """

        configs = {
            'startup': '',
            'running': '',
            'candidate': '',
        }

        if retrieve in ('running', 'all'):
            command = [ 'show run-config commands' ]
            output = self._send_command(command)
            configs['running'] = output

        return configs


    def get_acl(self):
        """Get the output of show acl summary and show acl layer2 summary
        Returns:

        {
            "acl_l2": {
                "acl": {
                    "enabled": "yes|no"
                }
            }
            "acl_ipv4": {
                "acl": {
                    "enabled": "yes|no"
                }
            },
            "acl_ipv6": {
                "acl": {
                    "enabled": "yes|no"
                }
            }
        }

        """
        show_acl_layer2_summary = self._send_command('show acl layer2 summary')
        show_acl_summary = self._send_command('show acl summary')

        acl = {}
        key = ""

        for l in show_acl_layer2_summary.splitlines() + show_acl_summary.splitlines():
            if "Layer2 ACL Name" in l:
                key = "acl_l2"
                acl[key] = {}
                continue
            elif "IPv4 ACL Name" in l:
                key = "acl_ipv4"
                acl[key] = {}
                continue
            elif "IPv6 ACL Name" in l:
                key = "acl_ipv6"
                acl[key] = {}
                continue

            c = l.split()
            if len(c) == 2 and c[-1] in ["Yes", "No"]:
                acl[key].setdefault(c[0], {})
                acl[key][c[0]]["enabled"] = c[-1]

        return acl


    def get_wlan(self):
        """Get the output of:
            show wlan summary
            show wlan apgroups
            show flexconnect summary

        Returns:
        {
            "wlans": {
                "total": <number>,
                "wlans": [
                    {
                        "id": "",
                        "name": "",
                        "interface": "",
                        "status": "Enabled|Disabled"
                    }
                ]
            },
            "apgroups": {
                "total": <number>,
                "groups": [
                    "site-name": ""
                    "site-description": "",
                    "access-points": [
                        {
                            "name": "",
                            "slots": "",
                            "model": "",
                            "mac": "",
                            "location": "",
                            "port": "",
                            "country": "",
                            "priority": ""
                        }
                    ]
                ]
            }
            "flexconnectgroups": {
                "total": <number>,
                "groups": [
                    {
                        "groupname": "",
                        "apcount": ""
                    }
                ]
            }
        }
        """
        show_wlan_summary = self._send_command('show wlan summary')
        show_wlan_apgroups = self._send_command('show wlan apgroups')
        show_flexconnect_group_summary = self._send_command('show flexconnect group summary')

        rexWLAN = re.compile("^(?P<ID>[0-9]+)\s+(?P<NAME>.*\S)\s+(?P<STATUS>Enabled|Disabled)\s+(?P<INTERFACE>\S+).*$")
        rexAP = re.compile("^(?P<NAME>\S+)\s+(?P<SLOTS>[0-9]+)\s+(?P<MODEL>\S+)\s+(?P<MAC>[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2})\s+(?P<LOCATION>.*\S)\s+(?P<PORT>\S+)\s+(?P<COUNTRY>[A-Z]+)\s+(?P<PRIO>[0-9]+)$")
        rexFLEX = re.compile("^(?P<NAME>.*\S)\s+(?P<APCOUNT>[0-9]+)$")

        wlan = {
            "wlans": {
                "total": 0,
                "wlans": []
            },
            "apgroups": {
                "total": 0,
                "groups": []
                #"site-name": None,
                #"site-description": None,
                #"access-points": {
                #    "total": 0
                #}
            },
            "flexconnectgroups": {
                "total": 0,
                "groups": []
            }
        }

        # wlans
        for l in show_wlan_summary.splitlines():
            if 'Number of WLAN' in l:
                c = l.split()
                wlan["wlans"]["total"] = int(c[-1])
                continue
            m = rexWLAN.match(l)
            if m:
                wlan["wlans"]["wlans"].append({
                    "id": m.groupdict()["ID"],
                    "name": m.groupdict()["NAME"],
                    "interface": m.groupdict()["INTERFACE"],
                    "status": m.groupdict()["STATUS"]
                })
                continue

        # ap groups
        apgroup = None
        foundap = None
        for l in show_wlan_apgroups.splitlines():
            if 'Total Number of AP Groups' in l:
                c = l.split()
                wlan["apgroups"]["total"] = int(c[-1])
                continue
            if 'Site Name' in l:
                if apgroup:
                    wlan["apgroups"]["groups"].append(copy.deepcopy(apgroup))
                    apgroup = None

                c = l.split()
                apgroup = {
                    "site-name": c[-1],
                    "site-description": "",
                    "access-points": {
                        "total": 0,
                        "access-points": []
                    }
                }
                continue
            if 'Site Description' in l:
                c = l.split()
                apgroup["site-description"] = c[-1]
                continue
            m = rexAP.match(l)
            if apgroup and m:
                foundap = True
                apgroup["access-points"]["total"] += 1
                apgroup["access-points"]["access-points"].append({
                    "name": m.groupdict()["NAME"],
                    "slots": m.groupdict()["SLOTS"],
                    "model": m.groupdict()["MODEL"],
                    "mac": m.groupdict()["MAC"],
                    "location": m.groupdict()["LOCATION"],
                    "port": m.groupdict()["PORT"],
                    "country": m.groupdict()["COUNTRY"],
                    "priority": m.groupdict()["PRIO"]
                })
                continue

        if apgroup:
            wlan["apgroups"]["groups"].append(copy.deepcopy(apgroup))
            apgroup = None

        # FLEXconnect groups
        startcount = False
        for l in show_flexconnect_group_summary.splitlines():
            if 'Count:' in l:
                c = l.split()
                wlan["flexconnectgroups"]["total"] = int(c[-1])
                continue
            if 'Group Name' in l:
                startcount = True
                continue
            m = rexFLEX.match(l)
            if startcount and m:
                wlan["flexconnectgroups"]["groups"].append({
                    "name": m.groupdict()["NAME"],
                    "apcount": m.groupdict()["APCOUNT"]
                })

        return wlan



    def get_radius(self):
        """Get the output of show radius summary

        Returns a dictionary per server:
        {
                "authentication": [ {
                    "index": "",
                    "server": "",
                    "type": "",
                    "port": "",
                    "state": "",
                    "tout": "",
                    "mgmtout": "",
                    "rfc3576": ""
                } ],
                "accounting": [ {
                    "index": "",
                    "server": "",
                    "type": "",
                    "port": "",
                    "state": "",
                    "tout": "",
                    "mgmtout": "",
                    "rfc3576": ""
            } ]
        }
        """
        show_radius_summary = self._send_command('show radius summary')

        rexAAA = re.compile("^(?P<IDX>[0-9]+)\s+(?:\*)?\s+(?P<TYPE>\S+)\s+(?P<SERVER>\S+)\s+(?P<PORT>\S+)\s+(?P<STATE>\S+)\s+(?P<TOUT>\S+)\s+(?P<MGMTOUT>\S+)\s+(?P<RFC3576>\S+).*$")

        radius = {
            "authentication": [],
            "accounting": []
        }
        aaa = ""

        for line in show_radius_summary.splitlines():
            if "Authentication Servers" in line:
                aaa = "authentication"
            elif "Accounting Servers" in line:
                aaa = "accounting"
            if not aaa:
                continue
            m = rexAAA.match(line)
            if m:
                radius[aaa].append({
                        "index": m.groupdict()["IDX"],
                        "server": m.groupdict()["TYPE"],
                        "server": m.groupdict()["SERVER"],
                        "port": m.groupdict()["PORT"],
                        "state": m.groupdict()["STATE"],
                        "tout": m.groupdict()["TOUT"],
                        "mgmtout": m.groupdict()["MGMTOUT"],
                        "rfc3576": m.groupdict()["RFC3576"],
                   })

        return radius

    def get_tacacs(self):
        """Get the output of "show tacacs summary" for Cisco WLC.
        Returns a dictionary per server:
        {
                "authentication": [ {
                    "index": "",
                    "server": "",
                    "port": "",
                    "state": "",
                    "tout": "",
                    "mgmttout": ""
                } ],
                "authorization": [{
                    "index": "",
                    "server": "",
                    "port": "",
                    "state": "",
                    "tout": "",
                    "mgmttout": ""
                }]
                "accounting": [{
                    "index": "",
                    "server": "",
                    "port": "",
                    "state": "",
                    "tout": "",
                    "mgmttout": ""
                }]
        }
        """
        # get output from device
        show_tacacs_summary = self._send_command('show tacacs summary')

        rexAAA = re.compile("^(?P<IDX>[0-9]+)\s+(?P<SERVER>\S+)\s+(?P<PORT>\S+)\s+(?P<STATE>\S+)\s+(?P<TOUT>\S+)\s+(?P<MGMTOUT>\S+).*$")

        tacacs = {
            "authentication": [],
            "authorization": [],
            "accounting": []
        }
        aaa = ""

        for line in show_tacacs_summary.splitlines():
            if "Authentication Servers" in line:
                aaa = "authentication"
            elif "Authorization Servers" in line:
                aaa = "authorization"
            elif "Accounting Servers" in line:
                aaa = "accounting"
            if not aaa:
                continue
            m = rexAAA.match(line)
            if m:
                tacacs[aaa].append({
                        "index": m.groupdict()["IDX"],
                        "server": m.groupdict()["SERVER"],
                        "port": m.groupdict()["PORT"],
                        "state": m.groupdict()["STATE"],
                        "tout": m.groupdict()["TOUT"],
                        "mgmtout": m.groupdict()["MGMTOUT"],
                   })

        return tacacs


if __name__ == '__main__':
    import json
    d = CiscoWlcDriver("test", "test", "test")
    print(json.dumps(d.get_wlan(), indent=4))

