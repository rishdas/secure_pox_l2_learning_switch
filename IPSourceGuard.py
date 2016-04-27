from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.util import dpid_to_str
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger ()

class IPSpoofer (object):
    threshold = 1

    def __init__ (self):
        self.inport = 0
        self.count = 0

def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

class IPSourceGuard (object):
    
    ipSecTable = {
        "00:00:00:00:00:01" : "10.0.0.1",
        "00:00:00:00:00:02" : "10.0.0.2",
        "00:00:00:00:00:03" : "10.0.0.3",
        "00:00:de:ad:be:ef" : "10.0.0.5"
        }

    def __init__(self):
        core.openflow.addListeners (self)
        log.info("Starting IPSource Guard component")
        self.spoofers = dict()

    def _handle_ConnectionUP (self, event):
        log.info("Switch %s connected", dpid_to_str(event.dpid))
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)
        log.info("Hubifying %s", dpidToStr(event.dpid))


    def _handle_PacketIn (self, event):
        dpid = event.connection.dpid
        packet = event.parsed
        inport = event.port
        packetv4 = packet.find('ipv4')

        if packetv4 is not None:
            log.info("%s %s => %s %s", packet.src, packetv4.srcip.toStr(),
                     packet.dst, packetv4.dstip.toStr())
            try:
                entry = IPSourceGuard.ipSecTable[(packet.src).toStr()]
            except KeyError:
                return
            if entry != packetv4.srcip.toStr():
                log.info("IP spoofing detected!! From MAC=%s, forging IP=%s",packet.src, packetv4.srcip.toStr())
                senderMAC = (packet.src).toStr()
                if senderMAC in self.spoofers.keys():
                    self.spoofers[senderMAC].count += 1
                    self.spoofers[senderMAC].inport = inport
                else:
                    self.spoofers[senderMAC] = IPSpoofer()
                    self.spoofers[senderMAC].inport = inport
            
                if self.spoofers[senderMAC].count >= IPSpoofer.threshold:
                    log.info("IP Spoofing threshold achieved. Blocking port %d", self.spoofers[senderMAC].inport)
                    self.blockSpoofer (senderMAC, event)
                return

        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)

    def blockSpoofer (self, mac, event):
        spoofer = self.spoofers[mac]
        match = of.ofp_match(in_port = spoofer.inport)
        msg = of.ofp_flow_mod (match=match)
        msg.priprity = 100
        msg.idle_timeout = of.OFP_FLOW_PERMANENT
        msg.hard_timeout = of.OFP_FLOW_PERMANENT
        event.connection.send (msg)
        spoofer.count = 0

def launch ():
    core.registerNew (IPSourceGuard)

