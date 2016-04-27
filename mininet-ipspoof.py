#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.node import OVSSwitch,RemoteController,DefaultController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

from sys import exit, stdin, argv

class IPSpoofTopo (Topo):
    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )
        switch = self.addSwitch ('s1')
        for i in range(1,4):
            name = "h%d" % i
            mac = "00:00:00:00:00:0%d" % i
            ip = "10.0.0.%d/24" % i
            host = self.addHost (name,mac=mac,ip=ip)
            self.addLink (host,switch,bw=10,delay="1ms")
        spoofer = self.addHost ("spoofer",mac="00:00:de:ad:be:ef",ip="10.0.0.5/24")
        self.addLink(spoofer, switch)

def startIPSpoofing (host):
    for i in range(1, 10):
        for j in range(1, 4):
            host.cmd ("nping -S 10.0.0.%d 10.0.0.%d" % (5 + i, j))

def ipspoof_launch (doSpoof=False,controller=None):
    topo = IPSpoofTopo ()
    net = Mininet (topo=topo, link=TCLink, switch=OVSSwitch, controller=controller)
    spoofer = net.get('spoofer')
    net.start()
    if doSpoof:
        startIPSpoofing (spoofer)
    CLI(net)
    net.stop()

if __name__ == "__main__":
    doSpoof = False
    controller = DefaultController
    setLogLevel("info")
    if "spoof" in argv:
        doSpoof=True
    if "remote" in argv:
        controller = RemoteController
    ipspoof_launch (doSpoof,controller)
