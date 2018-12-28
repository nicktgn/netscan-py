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
CMD_NMAP_QUICK = "nmap -T4 -F {exclude} {target}"
CMD_NMAP_QUICK_PLUS = "nmap -sV -T4 -O -F --version-light {exclude} {target}"
CMD_ARP_HOST = "arp {}"
CMD_ARP_TABLE = "arp -a"

CMD_ARP_SCAN_WIN = "lib/arp-scan/arp-scan/Release(x64)/arp-scan.exe -t {}"


MAC_EXCLUDE_LIST = ["FF:FF:FF:FF:FF:FF"]

OFFLINE_COUNT_THRESHOLD = 3

system = platform.system()

TIMEOUT_FAST = 10    # 10 sec
TIMEOUT_NMAP = 240   # 4 min

STEPS = ['nmap', 'arp-scan', 'arp']


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
            timeout=TIMEOUT_FAST)
      except subprocess.TimeoutExpired:
         pass
   return out == 0


def nmap_net(subnet, exclude_list):
   hosts = []
   no_macs = []
   out = ""

   cmd = CMD_NMAP_QUICK_PLUS.format(
      exclude = exclude(exclude_list),
      target = subnet
      ).split()

   try:
      out = subprocess.check_output(cmd, timeout=TIMEOUT_NMAP).decode("utf-8",  errors='replace')
   except subprocess.TimeoutExpired:
      return hosts, no_macs, "nmap timeout"   

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
            hosts.append(host)
         else:
            no_macs.append(host)
         ip = None
         mac = None
         os = None

   return hosts, no_macs, None


def arp_host(ip):
   out = -1
   try:
      out = subprocess.call(CMD_ARP_HOST.format(ip).split(), timeout=TIMEOUT_FAST)
   except subprocess.TimeoutExpired:
      pass

   return out == 0


def arp_table():
   hosts = []
   out = ""

   try:
      out = subprocess.check_output(CMD_ARP_TABLE.split(), timeout=TIMEOUT_FAST).decode("utf-8", errors='replace')
   except subprocess.TimeoutExpired:
      return hosts, "arp timeout"
   
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

   return hosts, None


def arp_mac_format(mac):
   if system == 'Darwin':
      orig_split = ':'
   elif system == 'Windows':
      orig_split = '-'
   return ':'.join([part.upper() if len(part)==2 else '0{}'.format(part.upper()) for part in mac.split(orig_split)])


def arp_scan(subnet):
   hosts = []

   out = ""

   if system == 'Windows':
      cmd = CMD_ARP_SCAN_WIN.format(subnet).split()
      try:
         out = subprocess.check_output(cmd, timeout=TIMEOUT_FAST).decode("utf-8", errors='replace')
      except subprocess.TimeoutExpired:
         return hosts, "arp-scan timeout"

   if DEBUG:
      print(out)

   for line in out.splitlines():
      if system == 'Windows':
         m = re.match(r'^.* ([ABCDEF\d:]+) is ([\d\.]+).*$', line)

      if m:
         mac = arp_mac_format(m.group(1))
         ip = m.group(2)
         hosts.append({"mac": mac, "ip": ip})

   return hosts, None


def host_filtered(host_mac, host_ip, exclude_list, mac_exclude_list, network):
   if host_ip in exclude_list \
      or host_mac in mac_exclude_list \
      or ipaddress.ip_address(host_ip) not in network:
         return True
   return False


def update_hosts(hosts, host):
   if host['mac'] not in hosts:
      hosts[host['mac']] = host
   else:
      for key in host:
         if host[key]:
            hosts[host['mac']][key] = host[key]
   pass


def scan(subnet, exclude, exclude_mac, logger, do_arp_scan=False, do_nmap=False, do_arp=False):
   updates = {}
   errors = 0

   network = ipaddress.ip_network(subnet)

   exclude_list = set(exclude.split(','))
   broadcast_ip = str(network.broadcast_address)
   exclude_list.add(broadcast_ip)

   mac_exclude_list = set(exclude_mac.split(','))
   mac_exclude_list.update(MAC_EXCLUDE_LIST)

   # 1) ping broadcast 
   ping_broadcast(broadcast_ip)

   for step in STEPS:
      if step == 'nmap' and do_nmap:
         hosts, no_macs, error = nmap_net(subnet, exclude)
      elif step == 'arp-scan' and do_arp_scan:
         hosts, error = arp_scan(subnet)
      elif step == 'arp' and do_arp:
         hosts, error = arp_table()
      else:
         continue

      if error is not None:
         logger.error(error)
         errors += 1
         continue

      for host in hosts:
         if host_filtered(host['mac'], host['ip'], exclude_list, mac_exclude_list, network):
            continue

         update_hosts(updates, host)

   if len(updates) == 0 and errors > 0:
      return None

   return updates


def analyze_hosts(state, hosts):
   new_state = {}
   changes = []

   # add new hosts first
   for host_mac, host in hosts.items():
      if host_mac not in state['hosts']:
         new_state[host_mac] = {**host,
            'name': host_mac,
            'online': True,
            'change_at': time.time(),
            'offline_count': 0,
            'offline_at': 0
         }
         changes.append("NEW host {} ({} | {}) is online".format(host_mac, host['ip'], host['os']))

   # existing hosts
   for s_host_mac, s_host in state['hosts'].items():
      new_state[s_host_mac] = s_host

      # ONLINE -> OFFLINE
      if s_host['online'] and s_host_mac not in hosts:
         # remember when went offline
         if s_host['offline_count'] == 0:
            s_host['offline_at'] = time.time()

         # inlcrease offline counter
         if s_host['offline_count'] < OFFLINE_COUNT_THRESHOLD:
            s_host['offline_count'] += 1

         else:
            online_since = s_host['change_at']
            online_until = s_host['offline_at']
            s_host['offline_count'] = 0
            s_host['offline_at'] = 0
            s_host['online'] = False
            s_host['change_at'] = online_until
            duration = datetime.timedelta(seconds=online_until - online_since)

            changes.append("Host {name} ({ip} | {os}) went OFFLINE on {until}. Was online since {since} (duration: {duration})".format(
                  name=s_host['name'], 
                  ip=s_host['ip'], 
                  os=s_host['os'] if 'os' in s_host else None,
                  until=time.strftime("%a %b %d %H:%M:%S", time.localtime(online_until)),
                  since=time.strftime("%a %b %d %H:%M:%S", time.localtime(online_since)),
                  duration=str(duration)))

      # RESET OFFLINE COUNTER
      elif s_host['online'] and s_host_mac in hosts and s_host['offline_count'] > 0:
         s_host['offline_count'] = 0
         s_host['offline_at'] = 0

      # OFFLINE -> ONLINE
      elif not s_host['online'] and s_host_mac in hosts:
         offline_since = s_host['change_at']
         offline_until = time.time()

         s_host['online'] = True
         s_host['ip'] = hosts[s_host_mac]['ip']    # update IP if host is back online
         if 'os' in hosts[s_host_mac] and hosts[s_host_mac]['os']:
            s_host['os'] = hosts[s_host_mac]['os'] # update OS if exists
         s_host['change_at'] = offline_until
         duration = datetime.timedelta(seconds=offline_until - offline_since)

         changes.append("Host {name} ({ip} | {os}) went ONLINE on {until}. Was offline since {since} (duration: {duration})".format(
            name=s_host['name'], 
            ip=s_host['ip'], 
            os=s_host['os'] if 'os' in s_host else None,
            until=time.strftime("%a %b %d %H:%M:%S", time.localtime(offline_until)),
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
   exclude_mac = options.get("exclude-mac", "")
   do_nmap = options.get("nmap", False)
   do_arp_scan = options.get("arp-scan", False)
   do_arp = options.get("arp", False)

   logger = get_logger()

   state = read_state()

   while True:
      try: 
         print("Update timestamp: {}".format(time.strftime("%a %b %d %H:%M:%S", time.localtime(time.time()))))

         scanned_hosts = scan(subnet, exclude, exclude_mac, logger,
            do_nmap=do_nmap, 
            do_arp_scan=do_arp_scan,
            do_arp=do_arp)
         
         # some errors occured and there were no updates
         if scanned_hosts == None:
            continue

         changes = analyze_hosts(state, scanned_hosts)

         for change in changes:
            logger.info(change)

         write_state(state)

         time.sleep(10)

      except KeyboardInterrupt:
         logger.info("Saving state and exiting...")
         write_state(state)
         sys.exit(0)

      except Exception as e:
         logger.exception(e)
         raise
    
   raise

   pass


if __name__ == '__main__':
   main()