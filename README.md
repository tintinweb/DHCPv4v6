DHCPv4v6
========

low-level scapy based dhcp client script (ipv4 ipv6)

Todo
========
* make threadable
* support more dhcp states

Usage
========

	specific_macs=["00:11:22:33:44:50","00:11:22:33:44:51","00:11:22:33:44:52","00:11:22:33:44:53","00:11:22:33:44:54","00:11:22:33:44:60","00:11:22:33:44:61","00:11:22:33:44:62","00:11:22:33:44:63"]
	conf.checkIPaddr=False
	conf.iface="eth2"
	conf.verb=False
	for m in specific_macs:
	    c = DHCPv4Client()
	    c.send_discover(src_mac=m)
	    c.wait_for_response()
	    c.send_request()
	    c.wait_for_response()
	    print c
	for m in specific_macs:
	    c = DHCPv6Client()
	    c.send_discover(src_mac=m)
	    c.wait_for_response()
	    c.send_request()
	    c.wait_for_response()
	    print c