# Copyright 2014 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`bandwidth_test` --- Bandwidth tests
=========================================
"""
# Stdlib
import logging
import socket
import threading
import time
import unittest

# SCION
from endhost.sciond import SCIONDaemon
from lib.defines import ADDR_IPV4_TYPE, SCION_UDP_EH_DATA_PORT
from lib.log import init_logging
from lib.packet.host_addr import haddr_parse
from lib.packet.scion import SCIONPacket
from lib.packet.scion_addr import SCIONAddr
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.util import handle_signals

PACKETS_NO = 1000
PAYLOAD_SIZE = 1300
# Time interval between transmission of two consecutive packets
SLEEP = 0.000005


class TestBandwidth(unittest.TestCase):
    """
    Bandwidth testing. For this test a infrastructure must be running.
    """

    def receiver(self, rcv_sock):
        """
        Receives the packet sent by test() method.
        Measures goodput and packets loss ratio.
        """
        i = 0
        start = None
        timeout = 1
        while i < PACKETS_NO:
            try:
                packet, _ = rcv_sock.recv()
            except socket.timeout:
                logging.error("Timed out after only %d packets", i)
                # Account for the timeout interval itself
                start += timeout
                break
            if i == 0:
                # Allows us to wait as long as necessary for the first packet,
                # and then have timeouts for later packets.
                rcv_sock.sock.settimeout(timeout)
                start = time.time()
            i += 1
        duration = time.time() - start

        lost = PACKETS_NO - i
        rate = 100*(lost/PACKETS_NO)
        logging.info("Goodput: %.2fKBps Pkts received: %d Pkts lost: %d "
                     "Loss rate: %d%%" %
                     ((i*PAYLOAD_SIZE)/duration/1000, i, lost, rate))

    def test(self):
        """
        Bandwidth test method. Obtains a path to (2, 26) and sends PACKETS_NO
        packets (each with PAYLOAD_SIZE long payload) to a host in (2, 26).
        """
        addr = haddr_parse("IPv4", "127.1.19.254")
        topo_file = "../../topology/ISD1/topologies/ISD:1-AD:19.json"
        sender = SCIONDaemon.start(addr, topo_file)

        paths = sender.get_paths(2, 26)
        self.assertTrue(paths)

        rcv_sock = UDPSocket(
            bind=(str("127.2.26.254"), SCION_UDP_EH_DATA_PORT),
            addr_type=ADDR_IPV4_TYPE,
        )

        logging.info("Starting the receiver.")
        threading.Thread(
            target=thread_safety_net, args=(self.receiver, rcv_sock),
            name="BwT.receiver").start()

        payload = b"A" * PAYLOAD_SIZE
        dst = SCIONAddr.from_values(2, 26, haddr_parse("IPv4", "127.2.26.254"))
        spkt = SCIONPacket.from_values(sender.addr, dst, payload, paths[0])
        (next_hop, port) = sender.get_first_hop(spkt)
        logging.info("Sending %d payload bytes (%d packets x %d bytes )" %
                     (PACKETS_NO * PAYLOAD_SIZE, PACKETS_NO, PAYLOAD_SIZE))
        for _ in range(PACKETS_NO):
            sender.send(spkt, next_hop, port)
            time.sleep(SLEEP)
        logging.info("Sending finished")


if __name__ == "__main__":
    init_logging("../../logs/bw_test.log", console=True)
    handle_signals()
    TestBandwidth().test()
