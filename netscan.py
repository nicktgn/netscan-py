import os
import sys
import subprocess
import re
import socket
import ipaddress
import time
import logging
import datetime
import platform

import yaml


DEBUG = False

LOG_FILE = "logs/netscan.log"
STATE_FILE = "data/netscan_state.yml"

CMD_PING1 = "ping {}"
CMD_NMAP1 = "nmap {} {}"
CMD_ARP_HOST = "arp {}"
CMD_ARP_TABLE = "arp -a"

MAC_EXCLUDE_LIST = ["FF:FF:FF:FF:FF:FF"]

system = platform.system()


def get_logger():
   logger = logging.getLogger('netscan')
   formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
   file_hdlr = logging.FileHandler(LOG_FILE)
   file_hdlr.setFormatter(formatter)
   logger.addHandler(file_hdlr)
   
   std_hdlr = logging.StreamHandler(sys.stdout)
   std_hdlr.setFormatter(formatter)
   logger.addHandler(std_hdlr)

   logger.setLevel(logging.DEBUG)
   return logger


def read_args():
   positional = []
   options = {}
   args = sys.argv[1:]
   for arg in args:
      if not arg.startswith('--'):
         positional.append(arg)
      else:
         arg = arg.lstrip('--')
         split = arg.split('=')
         if len(split) == 2:
            k,v = split 
         else:
            k,v = split[0],True
         options[k] = v

   return (positional, options)


def exclude(exclude_list):
   if len(exclude_list) == 0:
      return ""
   return "--exclude {}".format(exclude_list)


def ping_broadcast(broadcast_ip):
   out = -1
   with open(os.devnull, 'w') as devnull:
      try:
         out = subprocess.call(
            CMD_PING1.format(broadcast_ip).split(),
            stdout=devnull if not DEBUG else None,
            timeout=10)
      except subprocess.TimeoutExpired:
         pass
   return out == 0


def nmap(subnet, exclude_list):
   hosts = {"no_mac": {}}

   out = subprocess.check_output(CMD_NMAP1.format(exclude(exclude_list), subnet).split()).decode("utf-8")
   
   if DEBUG:
      print(out)

   ip = None
   mac = None
   os = None
   for line in out.splitlines():
      m = re.match(r'^Nmap scan report[^\d\.]*([\d\.]+)$', line)
      if m:
         ip = m.group(1)

      m = re.match(r'^MAC Address:\s+([ABCDEF\d:]+)\s*(\((.*)\))?$', line)
      if m:
         mac = m.group(1)
         os = m.group(3)

      if ip:
         host = {"ip": ip, "os": os, "mac": mac}
         if mac:
            hosts[mac] = host
         else:
            hosts["no_mac"][ip] = host
         ip = None
         mac = None
         os = None

   return hosts

def arp_host(ip):
   out = subprocess.call(CMD_ARP_HOST.format(ip).split())

   return out == 0


def arp_table():
   hosts = []

   out = subprocess.check_output(CMD_ARP_TABLE.split()).decode("utf-8")
   
   if DEBUG:
      print(out)

   for line in out.splitlines():
      if system == 'Darwin':
         m = re.match(r'^.*\(([\d\.]+)\) at ([abcdef\d:]+)\s*.*$', line)
      elif system == 'Windows':
         m = re.match(r'^\s*([\d\.]+)\s*([abcdef\d-]+)\s*.*$', line)

      if m:
         ip = m.group(1)
         mac = arp_mac_format(m.group(2))
         hosts.append({"mac": mac, "ip": ip})

   return hosts


def arp_mac_format(mac):
   if system == 'Darwin':
      orig_split = ':'
   elif system == 'Windows':
      orig_split = '-'
   return ':'.join([part.upper() if len(part)==2 else '0{}'.format(part.upper()) for part in mac.split(orig_split)])


def scan(subnet, exclude_list, no_nmap=False):
   new_hosts = {}

   broadcast_ip = ipaddress.ip_network(subnet).broadcast_address
   ping_broadcast(broadcast_ip)

   if not no_nmap:
      nmap_hosts = nmap(subnet, exclude_list)

   # get arp tables
   arp_hosts = arp_table()

   exclude_list_split = exclude_list.split(',')
   
   for host in arp_hosts:
      arp_mac = host['mac']
      arp_ip = host['ip']
      
      if arp_ip in exclude_list_split:
         continue
      if arp_mac in MAC_EXCLUDE_LIST:
         continue

      if not no_nmap:
         if mac in nmap_hosts:
            new_hosts[arp_mac] = {**nmap_hosts[arp_mac], **host}
         else:
            new_hosts[arp_mac] = {**nmap_hosts['no_mac'][arp_ip], **host}
      else:
         new_hosts[arp_mac] = {**host, 'os': None}

   return new_hosts


def analyze_hosts(state, hosts):
   new_state = {}
   changes = []

   # add new hosts first
   for host_mac, host in hosts.items():
      if host_mac not in state['hosts']:
         new_state[host_mac] = {**host,
            'name': host_mac,
            'online': True,
            'time_change': time.time()
         }
         changes.append("NEW host {} ({} | {}) is online".format(host_mac, host['ip'], host['os']))

   # existing hosts
   for s_host_mac, s_host in state['hosts'].items():
      new_state[s_host_mac] = s_host

      # host is down
      if s_host_mac not in hosts:
         online_since = s_host['time_change']
         s_host['online'] = False
         s_host['time_change'] = time.time()
         duration = datetime.timedelta(seconds=s_host['time_change'] - online_since)

         changes.append("Host {name} ({ip} | {os}) is offline. Was online since {since} (duration: {duration})".format(
               name=s_host['name'], 
               ip=s_host['ip'], 
               os=s_host['os'] if 'os' in s_host else None,
               since=time.strftime("%a %b %d %H:%M:%S", time.localtime(online_since)),
               duration=str(duration)))

      # host is up, but was offline
      elif not s_host['online']:
         offline_since = s_host['time_change']
         s_host['online'] = True
         s_host['ip'] = hosts[s_host_mac]['ip']    # update IP if host is back online
         if 'os' in hosts[s_host_mac] and hosts[s_host_mac]['os']:
            s_host['os'] = hosts[s_host_mac]['os'] # update OS if exists
         s_host['time_change'] = time.time()
         duration = datetime.timedelta(seconds=s_host['time_change'] - offline_since)

         changes.append("Host {name} ({ip} | {os}) is online. Was offline since {since} (duration: {duration})".format(
            name=s_host['name'], 
            ip=s_host['ip'], 
            os=s_host['os'] if 'os' in s_host else None,
            since=time.strftime("%a %b %d %H:%M:%S", time.localtime(offline_since)),
            duration=str(duration)))

   state['hosts'] = new_state
   return changes


def read_state():
   if not os.path.exists(STATE_FILE):
      return {"start_time": time.time(), "hosts": {}}

   with open(STATE_FILE, 'r') as stream:
      return yaml.load(stream)
   pass


def write_state(state):
   with open(STATE_FILE, 'w') as stream:
      yaml.dump(state, stream, default_flow_style=False)
   pass      


def print_changes(changes):
   pass


def main():
   args, options = read_args()

   subnet = args[0]   
   exclude = options.get("exclude", "")
   no_nmap = options.get("no-nmap", False)

   logger = get_logger()

   state = read_state()

   while True:
      try: 
         scanned_hosts = scan(subnet, exclude, no_nmap)
         changes = analyze_hosts(state, scanned_hosts)

         for change in changes:
            logger.info(change)

         write_state(state)
      except (KeyboardInterrupt, SystemExit):
         print("Saving state and exiting...")
         write_state(state)
         sys.exit(0)

   pass


if __name__ == '__main__':
   main()