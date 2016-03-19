#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.node import OVSSwitch,RemoteController
from mininet.cli import CLI
from mininet.util import quietRun
from mininet.log import setLogLevel, info
from mininet.term import makeTerms

from sys import exit, stdin, argv
from re import findall
from time import sleep
import os

class ARPSpoofTopo (Topo):
    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )
        switch = self.addSwitch ('s1')
        for i in range(3):
            id = i+1
            name = "h%d" % id
            mac = "00:00:00:00:00:0%d" % id
            ip = "10.0.0.%d/24" % id
            host = self.addHost (name,mac=mac,ip=ip)
            self.addLink (host,switch,bw=10,delay="50ms")
        spoofer = self.addHost ("spoofer",mac="00:00:de:ad:be:ef",ip="10.0.0.5/24")
        self.addLink (spoofer,switch)

def startARPSpoofing (host):
    host.cmd ("arpspoof -i spoofer-eth0 -t 10.0.0.1 10.0.0.2 > /dev/null 2>&1 &")
    host.cmd ("arpspoof -i spoofer-eth0 -t 10.0.0.3 10.0.0.2 > /dev/null 2>&1 &")
    host.cmd ("arpspoof -i spoofer-eth0 -t 10.0.0.3 10.0.0.1 > /dev/null 2>&1 &")
    host.cmd ("arpspoof -i spoofer-eth0 -t 10.0.0.2 10.0.0.1 > /dev/null 2>&1 &")

def stopARPSpoofing(host):
    host.cmd("kill %arpspoof")

def arpspoof_launch (doSpoof=False):
    topo = ARPSpoofTopo ()
    net = Mininet (topo=topo, link=TCLink, switch=OVSSwitch) #, controller=RemoteController)
    spoofer = net.get('spoofer')
    net.start()
    if doSpoof:
        startARPSpoofing (spoofer)
    CLI(net)
    stopARPSpoofing(spoofer)
    net.stop()

if __name__ == "__main__":
    doSpoof = False
    setLogLevel("info")
    if "spoof" in argv:
        doSpoof=True
    arpspoof_launch (doSpoof)
