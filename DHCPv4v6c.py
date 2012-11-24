#! /usr/bin/env python
# vim:ts=4:sw=4:expandtab
'''
Created on Nov 21, 2012

@author: mortner
'''
from scapy.all import *
import random
try:
    import ipaddr
except:
    ipaddr = None
    print "ipaddr not supported! please download googles ipaddr.py"



class Limits:
    XID_MIN = 1
    XID_MAX = 900000000

class Common():
    def randomMAC(self,*args,**kwargs):
        return RandMAC()
    
    def randomIP(self,type=4):
        if ipaddr:
          if type==4:
              net= ipaddr.IPv4Network('0.0.0.0/0')
          elif type==6:
              net= ipaddr.IPv6Network('0::0/0')
              #IPv6 ftw
          return ipaddr.IPAddress(random.randrange(int(net.network)+1,int(net.broadcast)-1))
        else:
            if type==4:
                return ".".join(str(randint(1, 255)) for i in range(4))
            elif type==6:
                # taken from: http://stackoverflow.com/questions/7660485/how-to-generate-random-ipv6-address-using-pythonor-in-scapy
                M = 16**4
                return ":".join(("%x" % random.randint(0, M) for i in range(8))) 
        raise Exception("Type not supported")

  
    def randomHostname(self, length=8, charset=None):
        charset = charset or string.ascii_uppercase + string.digits
        return ''.join(random.choice(charset) for x in range(length))
    
    def calcCIDR(mask):
        mask = mask.split('.')
        bits = []
        for c in mask:
           bits.append(bin(int(c)))
        bits = ''.join(bits)
        cidr = 0
        for c in bits:
            if c == '1': cidr += 1
        return str(cidr)
    
    def mac_bin2str(self,binmac):
        import binascii
        mac=binascii.hexlify(binmac)[0:12]
        blocks = [mac[x:x+2] for x in xrange(0, len(mac), 2)]
        return ':'.join(blocks)
        
    def getArg(self,d,key,default=None,failvalue=None):
        try:
            if d.has_key(key) and d[key]:
                if failvalue:
                    return failvalue
                return d[key]
        except KeyError:
            pass
        return default


class ARPUtil():
    def detect_request(self,pkt):
        if ARP in pkt and pkt[ARP].op==1: return True
        return False
    
    def parseRequest(self, pkt):
        l = {}
        if self.detect_request(pkt):
            if pkt[ARP].op==1:               #who-has
                l['src_mac']=pkt[Ether].src
                l['dst_mac']=pkt[Ether].dst
        return l
    
    def gen_gratious_arp(self,src_mac=None,src_ip=None):
        src_mac = src_mac or Common().randomMAC()
        src_ip = src_ip or Common().randomIP(type=4)
        garp = Ether(src=src_mac,dst="ff:ff:ff:ff:ff:ff")/ARP(hwsrc=src_mac,psrc=src_ip,hwdst="00:00:00:00:00:00",pdst=src_ip)
        return garp
        
    def gen_gratious_arp_subnet(self,cidr_subnet,mac=None):
        for ip in Net(cidr_subnet):
            yield self.gratious_arp(src_ip=ip)


class ICMPv6Util():
    def detect_request(self,pkt):
        if ICMPv6ND_NS in pkt and ICMPv6NDOptSrcLLAddr: return True
        return False
        #print "<- ICMP REQUEST FROM [%s] -> [%s]"%(pkt[ICMPv6NDOptSrcLLAddr].lladdr,pkt[ICMPv6ND_NS].tgt)  
    
    def parse_request(self, pkt):
        l = {}
        if self.detect_request(pkt):
            if pkt[ICMP].type==8:               #request
                l['src_ip']=pkt[IP].src
                l['dst_ip']=pkt[IP].dst
                l['src_mac']=pkt[Ether].src
                l['dst_mac']=pkt[Ether].dst
        return l
    
    def gen_icmp_response(self,src_ip,dst_ip,dst_mac,src_mac=None):
        #todo: fix me
        return
        src_mac= src_mac or Common().randomMAC()
        icmp_resp=Ether(src=randomMAC(),dst=pkt.src)/IP(src=myip,dst=mydst)/ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)/"12345678912345678912"
        return icmp_resp 
         
class ICMPv4Util():
    def detect_request(self,pkt):
        if ICMP in pkt and pkt[ICMP].type==8: return True
        return False
    
    def parse_request(self, pkt):
        l = {}
        if self.detect_request(pkt):
            if pkt[ICMP].type==8:               #request
                l['src_ip']=pkt[IP].src
                l['dst_ip']=pkt[IP].dst
                l['src_mac']=pkt[Ether].src
                l['dst_mac']=pkt[Ether].dst
        return l
    
    def gen_icmp_response(self,src_ip,dst_ip,dst_mac,src_mac=None):
        src_mac= src_mac or Common().randomMAC()
        icmp_resp=Ether(src=randomMAC(),dst=pkt.src)/IP(src=myip,dst=mydst)/ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)/"12345678912345678912"
        return icmp_resp 
         


class DHCPv4Util():

    def messagetype2str(self, id):
        try:
            return DHCPTypes[id[0]]
        except KeyError:
            return "<unknown %s>"%repr(id)
        
    def str2messagetype(self,strtype):
        try:
            switch = dict((y,x) for x,y in DHCPTypes.iteritems())
            return switch[strtype]
        except KeyError:
            return "<unknown %s>"%repr(strtype)
    
    def gen_discover(self,src_mac=None,xid=None,hostname=None):
        src_mac=src_mac or Common().randomMAC()
        xid=xid or random.randint(Limits.XID_MIN, Limits.XID_MAX)
        hostname=hostname or Common().randomHostname()
        dhcp_discover =  Ether(src=src_mac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(src_mac)],xid=xid)/DHCP(options=[("message-type","discover"),("hostname",hostname),"end"])
        return dhcp_discover
    
    def detect_offer(self,pkt):
        if DHCP in pkt:
            if pkt[DHCP] and pkt[DHCP].options[0][1] == self.str2messagetype('offer'):          # option=dhcp offer
                return True
        return False
    
    def detect_nak(self,pkt):
        if DHCP in pkt:
            if pkt[DHCP] and pkt[DHCP].options[0][1] == self.str2messagetype('nak'):          # option=dhcp offer
                return True
        return False  

    def detect_ak(self,pkt):
        if DHCP in pkt:
            if pkt[DHCP] and pkt[DHCP].options[0][1] == self.str2messagetype('ak'):          # option=dhcp offer
                return True
        return False  

    def parse_offer(self,pkt):
        l = {}
        if self.detect_offer(pkt):
            l['server_ip'] = pkt[IP].src
            l['server_hwaddr'] =pkt[Ether].src
            #find subnet
            l['options'] = pkt[DHCP].options
            
            l['subnetmask'] = [opt[1] for opt in pkt[DHCP].options if opt[0]=='subnet_mask'][0]
            l['client_ip'] = pkt[BOOTP].yiaddr
            l['server_id'] = pkt[BOOTP].siaddr
            l['xid'] = pkt[BOOTP].xid
            l['client_hwaddr'] = Common().mac_bin2str(pkt[BOOTP].chaddr)
        return l
         
    def gen_request(self,src_mac,xid,server_id,client_ip,hostname=None):
        hostname = hostname or Common().randomHostname()
        dhcp_req = Ether(src=src_mac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(src_mac)],xid=xid)/DHCP(options=[("message-type","request"),("server_id",server_id),("requested_addr",client_ip),("hostname",hostname),("param_req_list","pad"),"end"])
        return dhcp_req
        
    def gen_release(self,src_mac,dst_mac,src_ip):
        cmac,dhcpsmac,cip,dhcpsip,cip,myxid
        dhcp_release = Ether(src=cmac,dst=dhcpsmac)/IP(src=cip,dst=dhcpsip)/UDP(sport=68,dport=67)/BOOTP(ciaddr=cip,chaddr=[mac2str(cmac)],xid=myxid,)/DHCP(options=[("message-type","release"),("server_id",dhcpsip),("client_id",chr(1),mac2str(cmac)),"end"])

class DHCPv6Util():
    """
        protocol specific stuff
    
    c2s -> solicit
    s2c -> advertise 
    c2s -> request
    s2c -> reply
    
    """
    def build_ether(self,mac):
        IPv6mcast="33:33:00:01:00:02"
        IPv6LL="fe80::20c:29ff:fe6b:bf5e"
        IPv6bcast="ff02::1:2"
        IPv6DHCP_CLI_Port=546
        IPv6DHCP_SRV_Port=547
        ethead=Ether(src=mac,dst=IPv6mcast)/IPv6(src=IPv6LL,dst=IPv6bcast)/UDP(sport=IPv6DHCP_CLI_Port,dport=IPv6DHCP_SRV_Port)
        return ethead
    
    def gen_discover(self,src_mac=None,xid=None,hostname=None):
        src_mac=src_mac or Common().randomMAC()
        xid=xid or random.randint(0x00,0xffffff)
        hostname=hostname or Common().randomHostname()
        
        ethead=self.build_ether(src_mac)
        cli_id=DHCP6OptClientId(duid=DUID_LLT(lladdr=src_mac,timeval=int(time.time())))
        dhcp_discover = ethead/DHCP6_Solicit(trid=xid)/cli_id/DHCP6OptIA_NA(iaid=0xf)/DHCP6OptRapidCommit()/DHCP6OptElapsedTime()/DHCP6OptOptReq(reqopts=[23,24])
        return dhcp_discover
        #print "-> Discover [cid:%s]"%(repr(str(dhcp_discover[DHCP6OptClientId].duid)))
        #sendp(dhcp_discover,verbose=0,iface=conf.iface)
        #filter = icmp6 or (udp and src port 547 and dst port 546)
    
    def gen_request(self,p_advertise,iaid=0xf,xid=None,options=[23,24]):      
        trid=xid or random.randint(0x00,0xffffff)
        ethead=self.build_ether(p_advertise[Ether].dst)
        srv_id=DHCP6OptServerId(duid=p_advertise[DHCP6OptServerId].duid)
        cli_id=p_advertise[DHCP6OptClientId]
        iana=DHCP6OptIA_NA(ianaopts=p_advertise[DHCP6OptIA_NA].ianaopts, iaid=iaid)
        dhcp_request=ethead/DHCP6_Request(trid=xid)/cli_id/srv_id/iana/DHCP6OptElapsedTime()/DHCP6OptOptReq( reqopts=[23,24])
        return dhcp_request  
 
    def detect_offer(self,pkt):
        if DHCP6_Advertise in pkt:
            if DHCP6OptIAAddress in pkt and DHCP6OptServerId in pkt:
                return True
        return False
    
    def parse_offer(self,pkt):
        l = {}
        if self.detect_offer(pkt):
            l['server_ip'] = repr(pkt[IPv6].src)
            l['server_hwaddr'] =pkt[Ether].src
            #find subnet
            l['client_ip'] = pkt[DHCP6OptIAAddress].addr
            l['server_id'] = repr(pkt[DHCP6OptServerId].duid.lladdr)
            l['client_id'] = repr(pkt[DHCP6OptClientId].duid.lladdr)
            l['client_hwaddr'] = Common().mac_bin2str(pkt[BOOTP].chaddr)
            #print("<- DHCPv6 ADVERTISE FROM [%s] -> [%s] - LEASE: IPv6[%s]"%(sip,cip,myip))
            #dhcp_req=build_request(pkt,options=range(30))
            #sendp(dhcp_req,verbose=0,iface=conf.iface)
            #print "-> ACK IPv6[%s]\n"%myip
        return l
  
    
class DHCPv4Client(object):
    server_ip=None
    server_hwaddr=None
    
    client_ip = None
    client_hwaddr = None
    
    client_xid = None
    server_xid = None
    server_id = None
    options = []
    hostname = None
    subnetmask = None
    
    
    genDHCP = None
    genICMP = None
    genARP = None
    callbacks = {}
    timeout_count = 0
    
    history = []
    
    def __init__(self):
        self.genDHCP = DHCPv4Util()
        self.genICMP = ICMPv4Util()
        self.genARP = ARPUtil()
        
    def __str__(self):
        return self.__repr__()
        
    def __repr__(self):
        return """DHCPv4 Client
        
        Interface: %s
        Verbosity: %s
        
        Client Configuration:                |      Server
        -------------------------------------|------------------------------
        IP        =        %-20s      %-20s
        HWAddr    =        %-20s      %-20s
        
        Hostname  =        %-20s              
        MASK      =        %-20s
        
        xID       =        %-20s      %-20s
        
        
        
        DHCP Specific
        --------------------
        serverID  =        %-20s
        Options   =        %-20s
        
        
        Registered Callbacks
        --------------------
        %s

        History
        --------------------
        %s
        """%(conf.iface,conf.verb,
             self.client_ip,
             self.server_ip,
             self.client_hwaddr,
             self.server_hwaddr,
             self.hostname,
             self.subnetmask,
             self.client_xid,
             self.server_xid,
             self.server_id,
             repr(self.options),
             self.callbacks,
             self.history)
    
    def send_discover(self,src_mac=None,xid=None,hostname=None):
        self.client_hwaddr=src_mac
        self.client_xid=xid or random.randint(Limits.XID_MIN, Limits.XID_MAX)
        self.hostname=Common().randomHostname()
        pkt = self.genDHCP.gen_discover(src_mac=self.client_hwaddr,xid=self.client_xid,hostname=self.hostname)
        print "discover"
        self.track_history()
        
        sendp(pkt)
    
    def send_request(self,src_mac=None,xid=None,server_id=None,client_ip=None,hostname=None):
        src_mac=src_mac or self.client_hwaddr
        xid=xid or self.server_xid
        server_id=server_id or self.server_id
        client_ip=client_ip or self.client_ip
        pkt = self.genDHCP.gen_request(src_mac,xid,server_id,client_ip=client_ip,hostname=self.hostname)
        print "request"
        self.track_history()       
        sendp(pkt)
    
    def detect_dhcp(self,pkt):
        if self.genDHCP.detect_offer(pkt):
            print "offer detected"
            data = self.genDHCP.parse_offer(pkt)
            
            if self.client_xid==data['xid']:
                self.update(data)
                self.exec_callback('dhcp_offer',pkt)
            else:
                self.exec_callback('dhcp_offer_foreign_xid',pkt)
        if self.genDHCP.detect_nak(pkt):
            print "NAK detected"
            self.exec_callback('dhcp_nak',pkt)
        if self.genDHCP.detect_ak(pkt):
            print "AK detected"
            self.exec_callback('dhcp_ak',pkt)
        if self.genICMP.detect_request(pkt):
            print "ICMPRequest"
            data = self.genICMP.parseRequest(pkt)
            self.exec_callback('icmp_request',pkt)
        if self.genARP.detect_request(pkt):
            print "ARP WhoHas"
            data = self.genARP.parseRequest(pkt)
            self.exec_callback('arp_request',pkt)
            
        
    
    def wait_for_response(self,timeout=3,tries=1):
        filter= "arp or icmp or (udp and src port 67 and dst port 68)"
        while tries >0:
            print "* waiting for packets .."
            sniff(filter=filter,prn=self.detect_dhcp, store=0,timeout=timeout,iface=conf.iface)
            tries-=1
            
        
    def register_callback(self,hook,func):
        self.callbacks[hook]=func
    
    def exec_callback(self,hook,args):
        self.track_history("Hook:"+str(hook))
        if self.callbacks.has_key(hook): self.callbacks[hook]()
    
    def update(self,l):
        self.server_ip= Common().getArg(l,'server_ip')
        self.server_hwaddr=Common().getArg(l,'server_hwaddr')
        
        self.client_ip = Common().getArg(l,'client_ip')
        self.client_hwaddr = Common().getArg(l,'client_hwaddr')
        
        self.server_xid = Common().getArg(l,'xid')
        self.server_id = Common().getArg(l,'server_id')
        self.options = Common().getArg(l,'options')
        self.subnetmask = Common().getArg(l,'subnetmask')
        
    def track_history(self,name=None):
        from inspect import stack
        name = name or stack()[1][3]
        self.history.append(name)


class DHCPv6Client(object):
    #todo: FIX DHCP6 client - this is just a rough merge
    server_ip=None
    server_hwaddr=None
    
    client_ip = None
    client_hwaddr = None
    
    client_xid = None
    server_xid = None
    server_id = None
    options = []
    hostname = None
    subnetmask = None
    
    p_advertise=None
    
    
    genDHCP = None
    genICMP = None
    genARP = None
    callbacks = {}
    timeout_count = 0
    
    history = []
    
    def __init__(self):
        self.genDHCP = DHCPv6Util()
        self.genICMP = ICMPv6Util()
        self.genARP = ARPUtil()
        
    def __str__(self):
        return self.__repr__()
        
    def __repr__(self):
        return """DHCPv6 Client
        
        Interface: %s
        Verbosity: %s
        
        Client Configuration:                |      Server
        -------------------------------------|------------------------------
        IP        =        %-20s      %-20s
        HWAddr    =        %-20s      %-20s
        
        Hostname  =        %-20s              
        MASK      =        %-20s
        
        xID       =        %-20s      %-20s
        
        
        
        DHCP Specific
        --------------------
        serverID  =        %-20s
        Options   =        %-20s
        
        
        Registered Callbacks
        --------------------
        %s

        History
        --------------------
        %s
        """%(conf.iface,conf.verb,
             self.client_ip,
             self.server_ip,
             self.client_hwaddr,
             self.server_hwaddr,
             self.hostname,
             self.subnetmask,
             self.client_xid,
             self.server_xid,
             self.server_id,
             repr(self.options),
             self.callbacks,
             self.history)
    
    def send_discover(self,src_mac=None,xid=None,hostname=None):
        self.client_hwaddr=src_mac
        self.client_xid=xid or random.randint(Limits.XID_MIN, Limits.XID_MAX)
        self.hostname=Common().randomHostname()
        pkt = self.genDHCP.gen_discover(src_mac=self.client_hwaddr,xid=self.client_xid,hostname=self.hostname)
        print "discover"
        self.track_history()
        sendp(pkt)
    
    def send_request(self,p_advertise=None,iaid=0xf,xid=None,options=[23,24]):
        p_advertise=p_advertise or self.p_advertise
        if not p_advertise:
            print "no offer detected!"
            return
        xid=xid or self.server_xid
        pkt = self.genDHCP.gen_request(p_advertise,iaid=iaid,xid=xid,options=options) 
        print "request"
        self.track_history()       
        sendp(pkt)
    
    def detect_dhcp(self,pkt):
        if self.genDHCP.detect_offer(pkt):
            print "offer detected"
            data = self.genDHCP.parse_offer(pkt)
            self.p_advertise=pkt
            self.update(data)
            self.exec_callback('dhcp_offer',pkt)

        if self.genICMP.detect_request(pkt):
            print "ICMPv6Request"
            data = self.genICMP.parseRequest(pkt)
            self.exec_callback('icmp_request',pkt)
        if self.genARP.detect_request(pkt):
            print "ARP WhoHas"
            data = self.genARP.parseRequest(pkt)
            self.exec_callback('arp_request',pkt)
            
        
    
    def wait_for_response(self,timeout=3,tries=1):
        filter= "arp or icmp or (udp and src port 67 and dst port 68)"
        while tries >0:
            print "* waiting for packets .."
            sniff(filter=filter,prn=self.detect_dhcp, store=0,timeout=timeout,iface=conf.iface)
            tries-=1
            
        
    def register_callback(self,hook,func):
        self.callbacks[hook]=func
    
    def exec_callback(self,hook,args):
        self.track_history("Hook:"+str(hook))
        if self.callbacks.has_key(hook): self.callbacks[hook]()
    
    def update(self,l):
        self.server_ip= Common().getArg(l,'server_ip')
        self.server_hwaddr=Common().getArg(l,'server_hwaddr')
        
        self.client_ip = Common().getArg(l,'client_ip')
        self.client_hwaddr = Common().getArg(l,'client_hwaddr')
        
        self.server_xid = Common().getArg(l,'xid')
        self.server_id = Common().getArg(l,'server_id')
        self.options = Common().getArg(l,'options')
        self.subnetmask = Common().getArg(l,'subnetmask')
        
    def track_history(self,name=None):
        from inspect import stack
        name = name or stack()[1][3]
        self.history.append(name)
        




if __name__=="__main__":
    specific_macs=["00:11:22:33:44:50","00:11:22:33:44:51","00:11:22:33:44:52","00:11:22:33:44:53","00:11:22:33:44:54","00:11:22:33:44:60","00:11:22:33:44:61","00:11:22:33:44:62","00:11:22:33:44:63"]
    conf.checkIPaddr=False
    conf.iface="eth2"
    conf.verb=False
    for m in specific_macs:
        c = DHCPv6Client()
        c.send_discover(src_mac=m)
        c.wait_for_response()
        c.send_request()
        c.wait_for_response()
        print c