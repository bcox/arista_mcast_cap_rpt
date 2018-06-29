import struct
import binascii

class pcap_file():
    def __init__(self, filename):
        self.f = open(filename, 'rb') #read the file in binary mode
        header_data = self.f.read(24) #read global_header
        self.global_header = decode_pcap_global_header(header_data) #decode the global_header

    def next_packet(self):
        header_data = self.f.read(16) #read pcap_packet_header
        if not len(header_data): #check to see if we are done
            return None
        packet = decode_pcap_packet(header_data) #decode the packet
        packet.data = self.f.read(packet.incl_len) #read the included packet_data
        packet.db = {}
        decode_frame(packet.data, packet.db)
        return packet
#
class decode_pcap_global_header():
    def __init__(self, data):
        unpacked = struct.unpack('IHHiIII', data)
        self.magic_number = unpacked[0]
        self.swapped = self.magic_number != 0xa1b2c3d4
        self.version_major = unpacked[1]
        self.version_minor = unpacked[2]
        self.thiszone = unpacked[3]
        self.sigfigs = unpacked[4]
        self.snaplen = unpacked[5]
        self.network = unpacked[6]
#
class decode_pcap_packet():
    def __init__(self, header_data):
        unpacked = struct.unpack('IIII', header_data)
        self.ts_sec = unpacked[0]
        self.ts_usec = unpacked[1]
        self.incl_len = unpacked[2]
        self.orig_len = unpacked[3]
#
class decode_frame():
    def __init__(self, data, db):
        unpacked = struct.unpack_from('6s6s2s', data)
        db['eth_dst'] = binascii.hexlify(unpacked[0])
        db['eth_src'] = binascii.hexlify(unpacked[1])
        ip_type = binascii.hexlify(unpacked[2])
        packet_data = data[14:] #slice out the ethernet header
        if ip_type == '0800':
            decode_ip(packet_data, db)
#
class decode_ip():
    def __init__(self, data, db):
        db['type'] = 'IP'
        ip_data = binascii.hexlify(data)
        #print 'ip_data: ', ip_data
        db['ver'] = int(ip_data[:1], 16)
        ip_len = int(ip_data[1:2], 16) * 4
        db['tos'] = int(ip_data[2:4], 16)
        db['tos_cs'] = int(format(db['tos'], 'b')[:3],2)
        db['dscp'] = int(format(db['tos'], 'b')[:6],2)
        proto = int(ip_data[18:20], 16)
        db['src_ip'] = decode_ip.hex_ip_to_ipv4(self,ip_data[24:32])
        db['dst_ip'] = decode_ip.hex_ip_to_ipv4(self,ip_data[32:40])
        #print 'ver:', db['ver'], 'ip_len:', ip_len, 'tos:', db['tos'], 'proto:', proto, 'src_ip:', db['src_ip'], 'dst_ip:', db['dst_ip']
        transport_data = data[ip_len:]
        if proto == 17:
            decode_udp(transport_data, db)
        elif proto == 6:
            decode_tcp(transport_data, db)
        else:
            return
            print proto

    def hex_ip_to_ipv4(self, data):
        ip = []
        for i in xrange(0, len(data), 2):
            d = data[i:i+2]
            s = str(int(d, 16))
            ip.append(s)
        ip = '.'.join(ip)
        return ip
#
class decode_tcp():
    def __init__(self, data, db):
        db['transport'] = 'TCP'
        transport_data = binascii.hexlify(data)
        #print 'transport_data: ', transport_data
        db['sprt'] = int(transport_data[:4],16)
        db['dprt'] = int(transport_data[4:8],16)
        #print 'sprt:', db['sprt'], 'dprt', db['dprt']
#
class decode_udp():
    def __init__(self, data, db):
        db['transport'] = 'UDP'
        transport_data = binascii.hexlify(data)
        #print 'transport_data: ', transport_data
        db['sprt'] = int(transport_data[:4],16)
        db['dprt'] = int(transport_data[4:8],16)
        #print 'sprt:', db['sprt'], 'dprt', db['dprt']
#
