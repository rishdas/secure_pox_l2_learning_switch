from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import *
from pox.lib.util import dpid_to_str

log = core.getLogger ()

class ARPSpoofer (object):
    threshold = 3

    def __init__ (self):
        self.inport = 0
        self.count = 0

class DynamicARPInspection (object):
    
    secARPtable = {
        "10.0.0.1" : "00:00:00:00:00:01",
        "10.0.0.2" : "00:00:00:00:00:02",
        "10.0.0.3" : "00:00:00:00:00:03"
        }

    def __init__(self):
        core.openflow.addListeners (self)
        log.info("Starting DynamicARPInspection component")
        self.spoofers = dict()

    def _handle_ConnectionUP (self, event):
        log.info("Switch %s connected", dpid_to_str(event.dpid))

    def _handle_PacketIn (self, event):
        packet = event.parsed
        inport = event.port
        arp = packet.find ('arp')
        if arp is not None and arp.opcode == pkt.arp.REPLY:
            senderIP = arp.protosrc.toStr()
            senderMAC = arp.hwsrc.toStr()
            try:
                entry = DynamicARPInspection.secARPtable[senderIP]
            except KeyError:
                return
            if entry != senderMAC:
                log.info("ARP spoofing detected!! From MAC=%s, forging IP=%s",senderMAC,senderIP)
                if senderMAC in self.spoofers.keys():
                    self.spoofers[senderMAC].count += 1
                    self.spoofers[senderMAC].inport = inport
                else:
                    self.spoofers[senderMAC] = ARPSpoofer()
                    self.spoofers[senderMAC].inport = inport
            
                if self.spoofers[senderMAC].count > ARPSpoofer.threshold:
                    log.info("ARP Spoofing threshold achieved. Blocking port %d", self.spoofers[senderMAC].inport)
        

def launch ():
    core.registerNew (DynamicARPInspection)
