# -*- coding: utf-8 -*-
import os
import sys
import socket
import time
import traceback
import netifaces as nif
import pcapy
from pcapy import findalldevs, open_live

from impacket import ImpactPacket, structure
from impacket.dhcp import DhcpPacket
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder

if sys.platform == 'win32':
    import wmi


class BaseDecoder(object):
    def __init__(self, pcapObj, to_s):
        datalink = pcapObj.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception('Datalink type not supported: %s' % datalink)

        self.laddr = None
        self.lmask = None
        self.pcap = pcapObj
        self.timeout = to_s
        self.done = False

    def run(self):
        start_ts = time.time()
        try:
            while time.time() - start_ts < self.timeout and not self.done:
                self.pcap.dispatch(1, self.packetHandler)
        except Exception, e:
            detail = traceback.format_exc()
            print 'Stop capturing packet due to exception: %s, %s' % (e.message, detail)

    def packetHandler(self, hdr, data):
        pass


class ArpAndDhcpMonitor(BaseDecoder):
    def __init__(self, pcapObj, to_s, local_mac,
                 sip='169.254.123.1', cip='169.254.123.100', mask='255.255.255.0',
                 dns='169.254.123.1', router='169.254.123.1', lease=86400):
        super(ArpAndDhcpMonitor, self).__init__(pcapObj, to_s)

        self.predef_lease = lease
        self.predef_sip = sip
        self.predef_cip = cip
        self.predef_mask = mask
        self.predef_dns = dns
        self.predef_router = router

        if not isinstance(local_mac, str):
            raise Exception('Local MAC address must be given in ":" separated 6-element canonical form')
        self.local_mac_str = local_mac
        self.local_mac = bytearray(local_mac.replace(':', '').decode('hex'))

    def packetHandler(self, hdr, data):
        eth = self.decoder.decode(data)
        eth_type = eth.get_ether_type()
        src_mac = ImpactPacket.Ethernet.as_eth_addr(eth.get_ether_shost())

        if src_mac == self.local_mac_str:
            # 忽略所有从本地网卡发出的数据包
            return

        if eth_type == ImpactPacket.ARP.ethertype:
            # 收到 ARP 包
            arp = eth.child()
            op_name = arp.get_op_name(arp.get_ar_op())
            saddr = arp.as_pro(arp.get_ar_spa())
            taddr = arp.as_pro(arp.get_ar_tpa())

            if op_name == 'REQUEST' and saddr != '0.0.0.0' and saddr == taddr:
                # 对端已经有 IP，将本地 IP 设为与其同一子网
                print 'Got gratuitous ARP packet'
                local_addr = arp.get_ar_spa()
                if local_addr[-1] + 1 > 254:
                    local_addr[-1] -= 1
                else:
                    local_addr[-1] += 1

                # 设置本地 IP 并结束抓包
                self.laddr = arp.as_pro(local_addr)
                self.lmask = '255.255.255.0'
                self.done = True
        elif eth_type == ImpactPacket.IP.ethertype:
            # 收到 IP 包
            ip = eth.child()
            src_addr = ip.get_ip_src()
            dst_addr = ip.get_ip_dst()

            if ip.get_ip_p() == ImpactPacket.UDP.protocol:
                udp = ip.child()
                src_port = udp.get_uh_sport()
                dst_port = udp.get_uh_dport()

                if src_addr == '0.0.0.0' \
                        and dst_addr == '255.255.255.255' \
                        and src_port == 68 \
                        and dst_port == 67:
                    # 收到非本网卡发送的 DHCP 请求广播包，解析数据包
                    dhcp = DhcpPacket(udp.get_data_as_string())
                    msg_type = dhcp.getOptionValue('message-type')

                    # 构造 DHCP 响应包公用字段
                    dhcp_r = DhcpPacket()
                    dhcp_r['op'] = DhcpPacket.BOOTREPLY
                    dhcp_r['xid'] = dhcp['xid']
                    dhcp_r['secs'] = dhcp['secs']
                    dhcp_r['yiaddr'] = structure.unpack('!L', socket.inet_aton(self.predef_cip))[0]
                    dhcp_r['siaddr'] = structure.unpack('!L', socket.inet_aton(self.predef_sip))[0]
                    dhcp_r['chaddr'] = dhcp['chaddr']
                    dhcp_r['cookie'] = dhcp['cookie']

                    opts = [
                        ('subnet-mask', structure.unpack('!L', socket.inet_aton(self.predef_mask))[0]),
                        ('lease-time', self.predef_lease),
                        ('server-id', structure.unpack('!L', socket.inet_aton(self.predef_sip))[0]),
                        ('router', (structure.unpack('!L', socket.inet_aton(self.predef_router))[0],)),
                        ('domain-name-server', (structure.unpack('!L', socket.inet_aton(self.predef_dns))[0],)),
                    ]
                    if msg_type == DhcpPacket.DHCPDISCOVER:
                        print 'Got DHCP discover packet, responds with DHCP offer packet'

                        opts.append(('message-type', DhcpPacket.DHCPOFFER))
                    elif msg_type == DhcpPacket.DHCPREQUEST:
                        print 'Got DHCP request packet, responds with DHCP ack packet'

                        dhcp_r['ciaddr'] = structure.unpack('!L', socket.inet_aton(self.predef_cip))[0]
                        opts.append(('message-type', DhcpPacket.DHCPACK))

                        # DHCP ACK 响应发送后即完成 IP 配置过程
                        # 设置本地 IP 并结束抓包
                        self.laddr = self.predef_sip
                        self.lmask = self.predef_mask
                        self.done = True

                    # 依次构造 Ethernet/IP/UDP/DHCP 包结构
                    dhcp_r['_options'] = dhcp_r.packOptions(opts)
                    data = ImpactPacket.Data(str(dhcp_r))

                    udp_r = ImpactPacket.UDP()
                    udp_r.set_uh_sport(67)
                    udp_r.set_uh_dport(68)
                    udp_r.contains(data)

                    ip_r = ImpactPacket.IP()
                    ip_r.set_ip_src(self.predef_sip)
                    ip_r.set_ip_dst(self.predef_cip)
                    ip_r.contains(udp_r)

                    eth_r = ImpactPacket.Ethernet()
                    eth_r.set_ether_shost(self.local_mac)
                    eth_r.set_ether_dhost(eth.get_ether_shost())
                    eth_r.contains(ip_r)

                    # 通过 PCAP 发送响应包
                    self.pcap.sendpacket(eth_r.get_packet())


def get_interface():
    if sys.platform == 'win32':
        # Windows 系统，找到首个有线网卡
        # 遍历所有有线网卡配置找到对应 UUID 的配置，并设置为静态地址
        c = wmi.WMI()
        wql = "select * from Win32_NetworkAdapter where AdapterTypeId=0 and NetConnectionID is not null"
        for iface in c.query(wql):
            for ifconf in c.Win32_NetworkAdapterConfiguration(Index=iface.Index):
                uuid = ifconf.SettingID
                dev = '\\Device\\NPF_%s' % uuid
                mac_addr = ifconf.MACAddress
                return dev, mac_addr
    else:
        # 其他系统，人工选择
        ifs = findalldevs()
        if 0 == len(ifs):
            print "You don't have enough permissions to open any interface on this system."
            sys.exit(1)
        elif 1 == len(ifs):
            print 'Only one interface present, defaulting to it.'
            return ifs[0]

        count = 0
        for iface in ifs:
            print '%i - %s' % (count, iface)
            count += 1
        idx = int(raw_input('Please select an interface: '))
        dev = ifs[idx]
        try:
            mac_addr = nif.ifaddresses(dev)[nif.AF_LINK][0]['addr']
        except:
            mac_addr = None
        return dev, mac_addr


def set_local_if(dev, addr, mask):
    print 'Set local interface %s address to %s/%s' % (dev, addr, mask)
    sys_id = sys.platform
    if sys_id == 'win32':
        # Windows 系统
        import re

        res = re.search('({.+})', dev)
        if not res:
            raise Exception('Unknown format of windows network adapter %s' % dev)
        uuid = res.group(1)

        # 遍历所有有线网卡配置找到对应 UUID 的配置，并设置为静态地址
        c = wmi.WMI()
        wql = "select * from Win32_NetworkAdapter where AdapterTypeId=0 and NetConnectionID is not null"
        for iface in c.query(wql):
            for ifconf in c.Win32_NetworkAdapterConfiguration(Index=iface.Index):
                if ifconf.SettingID == uuid:
                    # 找到抓包网卡，设置静态地址
                    ifconf.EnableStatic(IPAddress=[unicode(addr)], SubnetMask=[unicode(mask)])
                    return
        # 没有找到关联网卡，报错退出
        raise Exception('Failed to find windows network adapter %s' % dev)
    else:
        # 类 UNIX 系统，要求 root 权限！
        os.system('ifconfig %s inet %s netmask %s' % (dev, addr, mask))


def main():
    dev, mac_addr = get_interface()
    if not mac_addr:
        print 'The network interface %s has no available MAC address!' % dev
        sys.exit(1)
    print 'Proceed on network interface %s (MAC %s) ...' % (dev, mac_addr)

    # 监听对端网卡静态 IP 配置时可能发出的保持 IP 地址用 ARP 包和动态 IP 配置时可能发出的 DHCP 包
    p = open_live(dev, 65535, 0, 100)
    print 'Begin processing ARP & DHCP packets ...'
    ds = ArpAndDhcpMonitor(p, 30, mac_addr)
    ds.run()
    print 'Finished processing ARP & DHCP packets...'

    if ds.laddr is None:
        # 没有收到对端发送的任何 DHCP 请求，无法完成自动配置
        raise Exception('Failed to receive any ARP or DHCP requests from peer!')

    set_local_if(dev, ds.laddr, ds.lmask)


if __name__ == '__main__':
    main()
