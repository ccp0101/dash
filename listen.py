#!/usr/bin/env python2

import pcap
import sys
import os


MIN_INTERVAL = 8


if __name__=='__main__':
    if len(sys.argv) < 4:
        print 'usage: listen.py <interface> <mac address> <command>'

    dev = sys.argv[1]
    mac = sys.argv[2]
    cmd = sys.argv[3]

    p = pcap.pcapObject()
    net, mask = pcap.lookupnet(dev)

    state = {
        "last_press_ts": 0.0
    }

    p.open_live(dev, 1600, 0, 100)
    p.setfilter("ether host %s and udp and (port 67 or port 68)" % mac, 0, 0)

    def on_match(pktlen, data, timestamp):
        if timestamp > (state["last_press_ts"] + MIN_INTERVAL):
            state["last_press_ts"] = timestamp
            print "Dash button %s pressed." % mac
            os.system(cmd)

    try:
        while 1:
            p.dispatch(1, on_match)

    except KeyboardInterrupt:
        print '%s' % sys.exc_type
        print 'shutting down'
        print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
