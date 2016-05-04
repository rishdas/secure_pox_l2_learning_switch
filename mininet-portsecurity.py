#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.node import OVSSwitch,RemoteController,DefaultController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

from sys import exit, stdin, argv

class PortSecurityTopo (Topo):
    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )
        switch = self.addSwitch ('s1')
        for i in range(1,6):
            name = "h%d" % i
            mac = "00:00:00:00:00:0%d" % i
            ip = "10.0.0.%d/24" % i
            host = self.addHost (name,mac=mac,ip=ip)
            self.addLink (host,switch,port1=1,port2=i,bw=10,delay="1ms")

def startPortSecurityTest (host,x):
    for i in range(1, 6):
        for j in range(1, 3):
                host.cmd ("nping --source-mac 0%d:00:00:00:00:%d%d 10.0.0.%d" % (x,i,j,j))

def portSecurity_launch (doSpoof=False,controller=None):
    topo = PortSecurityTopo ()
    net = Mininet (topo=topo, link=TCLink, switch=OVSSwitch, controller=controller)
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    h5 = net.get('h5')
    net.start()
    if doSpoof:
        startPortSecurityTest (h1,1)
        startPortSecurityTest (h2,2)
        startPortSecurityTest (h3,3)
        startPortSecurityTest (h4,4)
        startPortSecurityTest (h5,5)
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
    portSecurity_launch (doSpoof,controller)
