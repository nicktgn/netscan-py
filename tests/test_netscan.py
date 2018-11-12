from unittest import TestCase

from unittest import mock


import netscan


TIME1 = 235135.31352
TIME_CHANGE_OLD = 12345
TIME_CHANGE_NEW = 246810

TIME_CHANGE_OLD_STR = 'Thu Jan 01 11:25:45' 
TIME_DIFF = '2 days, 17:07:45'

timeMock1 = mock.MagicMock(return_value=TIME_CHANGE_NEW)



HOSTS_NEW1 = {
   "mac1": {'ip': 'ip1', 'mac': 'mac1', 'os':'os1'},
   "mac2": {'ip': 'ip2', 'mac': 'mac2', 'os':'os2'}
}
STATE1 = {
   "start_time": TIME1,
   "hosts": {
      "mac1": {'ip': 'ip1', 'mac': 'mac1', 'os':'os1', 'name': 'mac1', 'online': True, 'time_change': TIME_CHANGE_NEW},
      "mac2": {'ip': 'ip2', 'mac': 'mac2', 'os':'os2', 'name': 'mac2', 'online': True, 'time_change': TIME_CHANGE_NEW}
   }  
}
CHANGES1 = [
   "NEW host mac1 (ip1 | os1) is online",
   "NEW host mac2 (ip2 | os2) is online"
]

######################

STATE2 = {
   "start_time": TIME1,
   "hosts": {
      "mac1": {'ip': 'ip1', 'mac': 'mac1', 'os':'os1', 'name': 'mac1', 'online': True, 'time_change': TIME_CHANGE_OLD},
      "mac2": {'ip': 'ip2', 'mac': 'mac2', 'os':'os2', 'name': 'mac2', 'online': True, 'time_change': TIME_CHANGE_OLD}
   }  
}
HOSTS_NEW2 = {
   "mac3": {'ip': 'ip3', 'mac': 'mac3', 'os':'os3'}
}
CHANGES2 = [
   "NEW host mac3 (ip3 | os3) is online",
   "Host mac1 (ip1 | os1) is offline. Was online since {} (duration: {})".format(TIME_CHANGE_OLD_STR, TIME_DIFF),
   "Host mac2 (ip2 | os2) is offline. Was online since {} (duration: {})".format(TIME_CHANGE_OLD_STR, TIME_DIFF),
]
STATE2_1 = {
   "start_time": TIME1,
   "hosts": {
      "mac1": {'ip': 'ip1', 'mac': 'mac1', 'os':'os1', 'name': 'mac1', 'online': False, 'time_change': TIME_CHANGE_NEW},
      "mac2": {'ip': 'ip2', 'mac': 'mac2', 'os':'os2', 'name': 'mac2', 'online': False, 'time_change': TIME_CHANGE_NEW},
      "mac3": {'ip': 'ip3', 'mac': 'mac3', 'os':'os3', 'name': 'mac3', 'online': True, 'time_change': TIME_CHANGE_NEW}
   }  
}

#######################

STATE3 = {
   "start_time": TIME1,
   "hosts": {
      "mac1": {'ip': 'ip1', 'mac': 'mac1', 'os':'os1', 'name': 'name1', 'online': False, 'time_change': TIME_CHANGE_OLD},
      "mac2": {'ip': 'ip2', 'mac': 'mac2', 'os':'os2', 'name': 'name2', 'online': False, 'time_change': TIME_CHANGE_OLD}
   }  
}
HOSTS3 = {
   "mac1": {'ip': 'ip111', 'mac': 'mac1', 'os':'os111'},
   "mac2": {'ip': 'ip222', 'mac': 'mac2', 'os':'os222'}
}
CHANGES3 = [
   "Host name1 (ip111 | os111) is online. Was offline since {} (duration: {})".format(TIME_CHANGE_OLD_STR, TIME_DIFF),
   "Host name2 (ip222 | os222) is online. Was offline since {} (duration: {})".format(TIME_CHANGE_OLD_STR, TIME_DIFF),
]
STATE3_1 = {
   "start_time": TIME1,
   "hosts": {
      "mac1": {'ip': 'ip111', 'mac': 'mac1', 'os':'os111', 'name': 'name1', 'online': True, 'time_change': TIME_CHANGE_NEW},
      "mac2": {'ip': 'ip222', 'mac': 'mac2', 'os':'os222', 'name': 'name2', 'online': True, 'time_change': TIME_CHANGE_NEW},
   }  
}


def empty_state():
   return {"start_time": TIME1, "hosts": {}}


class NetscanTest(TestCase):
   def setUp(self):
      pass
   
   def tearDown(self):
      pass

   @mock.patch('time.time', timeMock1)
   def test_should_add_new_hosts_when_state_empty(self):
      state = empty_state()

      changes = netscan.analyze_hosts(state, HOSTS_NEW1)

      assert state == STATE1
      assert changes == CHANGES1
      pass

   @mock.patch('time.time', timeMock1)
   def test_should_add_new_host_and_offline_old_hosts(self):
      state = STATE2

      changes = netscan.analyze_hosts(state, HOSTS_NEW2)

      assert state == STATE2_1
      assert changes == CHANGES2
      pass

   @mock.patch('time.time', timeMock1)
   def test_should_change_host_to_online_and_update_ip_and_os(self):
      state = STATE3

      changes = netscan.analyze_hosts(state, HOSTS3)

      assert state == STATE3_1
      assert changes == CHANGES3
      pass

