#!/usr/bin/python
### Multicast capture script for determining health of multicast feed

"""
### returns the following format

Source: 10.10.10.1, Group: 239.0.0.1
Captured 50 packets, size min/max/avg: 78/78/78, pps: 10.0
data flows: (trans,source,port->dest,port tos: <tos/cs/dscp> count: <n>)
UDP,10.10.10.1,3033->239.0.0.1,62061 tos: 0/0/0': 50

### log messages created

Jun 29 13:47:35 wa488 FastCapi: 1038: %SYS-5-CONFIG_E: Enter configuration mode from console by local_command_api on command-api (unix:)
Jun 29 13:47:35 wa488 FastCapi: 1039: %SYS-5-CONFIG_I: Configured from console by local_command_api on command-api (unix:)
Jun 29 13:47:40 wa488 FastCapi: 1040: %SYS-5-CONFIG_E: Enter configuration mode from console by local_command_api on command-api (unix:)
Jun 29 13:47:41 wa488 FastCapi: 1041: %SYS-5-CONFIG_I: Configured from console by local_command_api on command-api (unix:)
"""

### Build connection to api
def build_connection():
    import os
    if os.path.exists('/var/run/command-api.sock'):
        from jsonrpclib import Server
        switch_api = Server( "unix:/var/run/command-api.sock")
        return switch_api
    else:
        exit("Socket API not available")
#

### retrive multicast group data
def pull_multicast_group_data(switch_api, db):
    ### look for group and collect interface data
    cmd = 'show ip mroute ' + db.group
    result = switch_api.runCmds(1,[cmd])
    if len(result[0]['groups'][db.group]['groupSources']) == 0: ### group does not exist
        exit("Group does not exist in mroute table")
    elif db.source == '*':
        ###
        ### need to delete '*' from dataset if it is there
        ###
        if len(result[0]['groups'][db.group]['groupSources']) >= 2:
            exit("Group has multiple sources, use -source in command")
        else:
            for key in result[0]['groups'][db.group]['groupSources']:
                db.in_int = result[0]['groups'][db.group]['groupSources'][key]['rpfInterface']
    elif db.source in result[0]['groups'][db.group]['groupSources']:
        db.in_int = result[0]['groups'][db.group]['groupSources'][db.source]['rpfInterface']
    else:
        exit("Group or source was not found in the mroute table")

### create/delete filter to limit data to the CPU
def create_filter(db):
    if db.source == '*':
        db.filter_name = 'auto-any-' + str(db.group).replace('.','_')
    else:
        db.filter_name = 'auto-' + str(db.source).replace('.','_') + '-' + str(db.group).replace('.','_')
    ###
    ###*** check if filter_name exists, report error if already in play
    ###
    db.commands.append('ip access-list ' + db.filter_name)
    db.commands.append('permit ip any ' + db.group + '/32')
    db.filter_created = 1

### mirror_to_cpu
def create_span_to_cpu(switch_api, db):
    ### verify span session available
    result = switch_api.runCmds(1,['show monitor session'])
    session_count = len(result[0]['sessions'].keys())
    if (session_count <= 4):
        db.commands.append('monitor session ' + db.filter_name + ' source ' + db.in_int + ' rx')
        db.commands.append('monitor session ' + db.filter_name + ' destination cpu')
        db.commands.append('monitor session ' + db.filter_name + ' ip access-group ' + db.filter_name)
        push_config(switch_api, db)
        result = switch_api.runCmds(1,['show monitor session ' + db.filter_name])
        db.mirror_int = result[0]['sessions'][db.filter_name]['mirrorDeviceName']
        db.mirror_created = 1
    else:
        exit("unable to create span session", session_count, "sessions already exist")
#

# use api to push commands into switch
def push_config(switch_api, db):
    if db.commands:
        db.commands.insert(0, 'enable')
        db.commands.insert(1, 'configure')
        db.commands.append('end')
        result = switch_api.runCmds(1,db.commands)
        db.commands = []
#

### create_pcap_file (using TCPDump)
def capture_data_to_file(switch_api, db):
    ###*** check directory exists / create it
    import os
    path = '/mnt/flash/mcast_cap'
    if not os.path.exists(path):
        os.mkdir(path)
    ### timeout 10 tcpdump -i mirror0 -w  myfile
    from subprocess import check_output
    date=(check_output('date +%Y%M%d_%H%M%S', shell=True)).strip()
    db.pcap_file = path + db.group + '_' + date + '.pcap'
    cmd = ('timeout ' +
        str(db.timeslice) +
        ' tcpdump -i ' +
        db.mirror_int +
        ' -w ' +
        db.pcap_file
        )
    from subprocess import check_output, CalledProcessError
    try:
        output=check_output(cmd, shell=True)
    except CalledProcessError as e:
        if e.returncode == 124:
            pass
        else:
            exit("'%s' failed, returned code %d" % (cmd,e.returncode))
#

### parse pcap ... get packet size (max, min, ave), Packets per second
### bonus look at the multicast header, if known type, look at sequance numbers to look for lost packets.
def parse_pcap_file(db):
    import read_pcap
    from collections import defaultdict

    flows = defaultdict(int)
    count = 0
    min_pkt = 100000
    max_pkt = 0
    tot_pkt = 0

    pcap_file = read_pcap.pcap_file(db.pcap_file)
    p = pcap_file.next_packet()
    while p != None:
        count+=1
        tot_pkt+=p.orig_len
        if min_pkt > p.orig_len:
            min_pkt = p.orig_len
        if max_pkt < p.orig_len:
            max_pkt = p.orig_len
        if 'transport' in p.db:
            flow = (
                p.db['transport'] + ',' +
                p.db['src_ip'] + ',' +
                str(p.db['sprt']) + '->' +
                p.db['dst_ip'] + ',' +
                str(p.db['dprt']) + ' tos: ' +
                str(p.db['tos']) + '/' +
                str(p.db['tos_cs']) + '/' +
                str(p.db['dscp'])
                )
            flows[flow] +=1
        p = pcap_file.next_packet()

    db.packets = count
    db.min_pkt = min_pkt
    db.max_pkt = max_pkt
    db.avg_pkt = tot_pkt/count
    db.pps = 1.0 * count/db.timeslice
    db.flows = flows
#

def is_valid_ipv4_address(address):
    import socket
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True
#
def is_valid_ipv6_address(address):
    import socket
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True
#
def is_valid_multicast(address):
    if ":" in address:
        print "IPv6 Multicast not currently supported"
        return False
    else:
        parts = address.split(".")
        if len(parts) != 4:
            return False
        if (int(parts[0]) >= 224 and int(parts[0]) <= 239):
            return True
        else:
            return False
#

# parse the command line data
def collect_arguments(db):
    import argparse

    parser = argparse.ArgumentParser(description='collect data on multicast group')
    parser.add_argument('group', type=str,
                    help='Multicast Group')
    parser.add_argument('-source', type=str,
                    help='Multicast Source')
    parser.add_argument('-save', action="store_true",
                    help='don\'t delete the PCAP file')
    parser.add_argument('-time', type=int,
                    help='number value of seconds to capture data default:' + str(db.timeslice))
    args = parser.parse_args()
    if args.save:
        db.save_pcap = 1
    if args.time:
        if args.time >= 3 and args.time <= 300:
            db.timeslice = args.time
        else:
            exit('time value must be greater than 2 and no more than 300')
    if (is_valid_ipv4_address(args.group) or is_valid_ipv6_address(args.group)):
        if is_valid_multicast(args.group):
            db.group = args.group
        else:
            exit('Invalid options use -h for help')
    else:
        exit('Invalid options use -h for help')
    if args.source:
        if (is_valid_ipv4_address(args.source) or is_valid_ipv6_address(args.source)):
            db.source = args.source
        else:
            exit('Invalid options use -h for help')
#

# print out the results
def print_data(db):
    print ("Source: %s, Group: %s" %(db.source,db.group))
    print ("Captured %d packets, size min/max/avg: %s/%s/%s, pps: %s"
        %(db.packets, db.min_pkt, db.max_pkt, db.avg_pkt, db.pps)
        )
    print 'data flows: (trans,source,port->dest,port tos: <tos/cs/dscp> count: <n>)'
    for k in sorted(db.flows):
        print ("  %s : %s" %(k, db.flows[k]))
    if db.save_pcap:
        print ("File saved: %s" %db.pcap_file)
#

# remove the configurations added and clean up the pcap unless flag set
def clean_up(switch_api, db):
    if db.mirror_created:
        db.commands.append('no monitor session ' + db.filter_name)
    if db.filter_created:
        db.commands.append('no ip access-list ' + db.filter_name)
    if db.commands:
        push_config(switch_api, db)
    if db.pcap_file:
        if db.save_pcap == 0:
            import os
            try:
                os.remove(db.pcap_file)
            except OSError, e:  ## if failed, report it back to the user ##
                print ("Error: %s - %s." % (e.filename,e.strerror))
#

class DB:
    timeslice = 5
    source = '*'
    save_pcap = 0
    commands = []

def Main():
    db = DB()
    collect_arguments(db)
    switch_api = build_connection()
    pull_multicast_group_data(switch_api, db)
    create_filter(db)
    create_span_to_cpu(switch_api, db)
    capture_data_to_file(switch_api, db)
    parse_pcap_file(db)
    clean_up(switch_api, db)
    print_data(db)
#
Main()
