#!/usr/bin/python3
#---------------------------------[Imports]------------------------------------
# Internal modules
from collections import Counter
import os
import pickle
import socket
import sys


# Downloaded modules
import matplotlib.pyplot as plt
from openpyxl import Workbook
from openpyxl import load_workbook
import pandas as pd
from prettytable import PrettyTable
from scapy.all import *
from scapy.all import Ether, DNS, DNSRR
from scapy.layers.http import HTTPRequest
import seaborn as sns
from tabulate import tabulate
from termcolor import colored, cprint

#---------------------------------[Globals]------------------------------------
global savepath

#--------------------------------[Functions]-----------------------------------
# Determines if directory path exists.
def ispath(path):
    if path.startswith('~'):
        return os.path.exists(path)
    elif path.startswith('/'):
        return os.path.exists(path)
    else:
        curdir = os.getcwd()
        curpath = curdir + '/' + path
        return os.path.exists(curpath)

# Used to convert a timestamp into human_time
def convert_ts(timestamp):
    local_time = time.localtime(timestamp)
    #human_time = time.asctime(local_time)
    my_time = time.strftime("%d/%m/%y\n%H:%M:%S" , local_time)
    return(my_time)

# Gets the OSI layers in the provided packets.
def __PacketLayers(pkt):
    i = 0
    while True:
        layer = pkt.getlayer(i)
        if layer is None:
            break
        yield layer
        i += 1

# Defines a list of packet layers in the provided packet.
def __GetPktLayers(pkt):
    pkt_layer = []
    packet = Ether(_pkt=pkt)
    for layer in __PacketLayers(pkt):
        pkt_layer.append(layer.name)

    return pkt_layer

# Reads the PCAP file and parses the data into a list of
# scapy.packet structures.
def __ReadPCAP(PCAP):
    packets = rdpcap(PCAP)
    return packets

# Collects the statistics for the provided packets.
def __GetStats(packets):
    __Duration(packets)

    __IPsrc_Top(packets)
    __IPsrc_Time(packets)
    
    __IPdest_Top(packets)
    __IPdest_Time(packets)
    
    __L3_Count(packets)
    __L3_Time(packets)

    __L4_Count(packets)
    __L4_Time(packets)
    
    __L5_Count(packets)
    __L5_Time(packets)

    
    __HTTP_Count(packets)
    __HTTP_Time(packets)
    
    __DNS_Count(packets)
    __DNS_Time(packets)
    
    __ARP_Count(packets)
    __ARP_Time(packets)
    
# Prints out the start and end of the capture based
# on packet timestamps
def __Duration(packets):
    times = []

    for pkt in packets:
        times.append(float(pkt.time))
    times.sort()

    start = convert_ts(times[0])
    print("Capture Start:\n" + start)

    end = convert_ts(times[-1])
    print("Capture End:\n" + end)


#----------------[Total Counts]----------------
# Count Graphs/Tables produced:
# -Total packets from IP source
# -Total packets from IP Destination
# -Total packets with Layer 3 Types
# -Total packets with Layer 4 Types
# -Total packets with Layer 5 Types
# -Total HTTP/HTTPS Requests made from source
# -Total DNS Queries made from source
# -Total ARP reqiests made from source

# Produces a Count bar graph from provided data.
def __GraphingCount(df, xName, Title, rotate): 
    global savepath
    sns.set_palette(sns.color_palette("magma"))

    plt = sns.countplot(data = df, x = xName)
    
    plt.set_xticklabels(plt.get_xticklabels(), fontsize=7, rotation=rotate)
    for p in plt.patches:
        plt.annotate(format(p.get_height(), '.0f'), (p.get_x() + p.get_width() / 2.,
        p.get_height()), ha = 'center', va = 'center', xytext = (0, 5),
        textcoords = 'offset points', fontsize=7)

    plt.figure.savefig((savepath + "/" + Title), bbox_inches = "tight")
    plt.figure.clf()


# Analyzes the provided packets, calculates the ammount
# of packets from an IP source overall and 
# generates a table and a graph displaying the data.
def __IPsrc_Top(packets):
    title = 'Top Source IPs from Capture'
    index = 'IP Source'
    filename = 'IPSource_Count.png'

    srcIP = []

    for pkt in packets:
        if IP in pkt:
            srcIP.append(pkt[IP].src)
        elif IPv6 in pkt:
            srcIP.append(pkt[IPv6].src)

    cnt = Counter()

    for ip in srcIP:
        cnt[ip] += 1
    

    print("\n" + title)
    table = PrettyTable([index, "Count"])

    for ip, count in cnt.most_common():
        table.add_row([ip, count])

    print(table)

    df = pd.DataFrame(srcIP, columns = [index])
    __GraphingCount(df, index, filename, 90)

    print("(" + filename + ")\n")

# Analyzes the provided packets, calculates the ammount
# of packets from an IP destination overall and 
# generates a table and a graph displaying the data.
def __IPdest_Top(packets):
    title = 'Top Destination IPs from Capture'
    index = 'IP Destination'
    filename = 'IPDest_Count.png'

    dstIP = []

    for pkt in packets:
        if IP in pkt:
            dstIP.append(pkt[IP].dst)
        elif IPv6 in pkt:
            dstIP.append(pkt[IPv6].dst)

    cnt = Counter()

    for ip in dstIP:
        cnt[ip] += 1
    

    print("\n" + title)
    table = PrettyTable([index, "Count"])

    for ip, count in cnt.most_common():
        table.add_row([ip, count])

    print(table)

    

    df = pd.DataFrame(dstIP, columns = [index])
    __GraphingCount(df, index, filename, 90)
    print("(" + filename + ")\n")

# Get a list of sessions.
def __SessionInfo(packets):
    print("\nSessions")
    sessions = packets.sessions()
    for sess in sessions:
        print(sess)

# Analyzes the provided packets, calculates the ammount
# of Layer 3 type packets overall and generates a table 
# and a graph displaying the data.
def __L3_Count(packets):
    title = 'Layer 3 Packet Count'
    index = 'L3 Types'
    filename = 'L3Type_Count.png'

    L3_types = []

    for pkt in packets:
        layers = __GetPktLayers(pkt)
        if len(layers) >= 2:
            L3_types.append(layers[1])

    cnt = Counter()

    for L3 in L3_types:
        cnt[L3] += 1

    print("\n" + title)
    table = PrettyTable([index, "Count"])

    for L3, count in cnt.most_common():
        table.add_row([L3, count])
    print(table) 

    df = pd.DataFrame(L3_types, columns = [index])
    __GraphingCount(df, index, filename, 0)
    print("(" + filename + ")\n")

# Analyzes the provided packets, calculates the ammount
# of Layer 4 type packets overall and generates a table 
# and a graph displaying the data.
def __L4_Count(packets):
    title = 'Layer 4 Packet Count'
    index = 'L4 Types'
    filename = 'L4Type_Count.png'

    L4_types = []

    for pkt in packets:
        layers = __GetPktLayers(pkt)
        if len(layers) >= 3:
            L4_types.append(layers[2])
            

    cnt = Counter()

    for L4 in L4_types:
        cnt[L4] += 1

    print("\n" + title)
    table = PrettyTable([index, "Count"])

    for L4, count in cnt.most_common():
        table.add_row([L4, count])
    print(table) 

    df = pd.DataFrame(L4_types, columns = [index])
    __GraphingCount(df, index, filename, 90)
    print("(" + filename + ")\n")

# Analyzes the provided packets, calculates the ammount
# of Layer 5 type packets overall and generates a table 
# and a graph displaying the data.
def __L5_Count(packets):
    title = 'Layer 5 Packet Count'
    index = 'L5 Types'
    filename = 'L5Type_Count.png'

    L5_types = []

    for pkt in packets:
        layers = __GetPktLayers(pkt)
        if len(layers) >= 4:
            L5_types.append(layers[3])

    cnt = Counter()

    for L5 in L5_types:
        cnt[L5] += 1

    print("\n" + title)
    table = PrettyTable([index, "Count"])

    data = []
    for L5, count in cnt.most_common():
        table.add_row([L5, count])
        
    df = pd.DataFrame(L5_types, columns = [index])
    print(table)
    __GraphingCount(df, index, filename, 90)
    print("(" + filename + ")\n")

# Analyzes the provided packets, calculates the ammount
# of HTTP/HTTPS type packets overall and generates a table 
# and a graph displaying the data.
def __HTTP_Count(packets):
    title = 'Top HTTP/HTTPS Requests'
    index = 'Request'
    filename = ''

    httpconvo = []

    for pkt in packets:
        if TCP in pkt and (str(pkt[TCP].dport) == "443" or str(pkt[TCP].sport) == "443"):
            if IP in pkt:
                ip = pkt[IP].src
                dest = pkt[IP].dst
            elif IPv6 in pkt:
                ip = pkt[IPv6].src
                dest = pkt[IPv6].dst

            httpconvo.append(ip + " -> https:" + dest)
        elif pkt.haslayer(HTTPRequest):
            try:
                url = pkt[HTTPRequest].Host.decode() + pkt[HTTPRequest].Path.decode()
                if IP in pkt:
                    ip = pkt[IP].src
                elif IPv6 in pkt:
                    ip = pkt[IPv6].src
                
                httpconvo.append(ip + " -> " + url)
            except:
                pass
        
    cnt = Counter()

    for convos in httpconvo:
        cnt[convos] += 1

    print("\n" + title)
    table = PrettyTable([index, "Count"])

    for request, count in cnt.most_common():
        table.add_row([request,count])
    
    print(table)
   
# Analyzes the provided packets, calculates the ammount
# of DNS type packets overall and generates a table 
# and a graph displaying the data.   
def __DNS_Count(packets):
    title = 'Top DNS name resolutions'
    index = 'Name'
    filename = 'DNSNameRes_Count.png'

    DNSname = []
    for pkt in packets:
        if DNS in pkt:
            for x in range(pkt[DNS].ancount):
                DNSname.append(pkt[DNSRR][x].rdata)

    cnt = Counter()

    for names in DNSname:
        cnt[names] += 1

    print("\n" + title)
    table = PrettyTable([index, "Count"])

    for name, count in cnt.most_common():
        table.add_row([name, count])
    
    print(table)
    df = pd.DataFrame(DNSname, columns = [index])
    __GraphingCount(df, index, filename, 90)
    print("(" + filename + ")\n")

# Analyzes the provided packets, calculates the ammount
# of ARP type packets overall and generates a table 
# and a graph displaying the data.
def __ARP_Count(packets):
    title = 'Total ARP requests by source'
    index = 'ARP Source'
    filename = 'ARPSource_Count.png'

    ARPs = []

    for pkt in packets:
        if ARP in pkt:
            ARPs.append(pkt[ARP].psrc + '(' +  pkt[Ether].src + ')')

    cnt = Counter()

    for sources in ARPs:
        cnt[sources] += 1

    print("\n" + title)
    table = PrettyTable([index, "Count"])

    for sources, count in cnt.most_common():
        table.add_row([sources, count])
    
    print(table)

    df = pd.DataFrame(ARPs, columns = [index])
    __GraphingCount(df, index, filename, 0)
    print("(" + filename + ")\n")

#----------------[Counts over Time]----------------
# Time Graphs/lists produced:
# -Total packets from IP source over time
# -Total packets from IP Destination over time
# -Total packets with Layer 3 Types over time
# -Total packets with Layer 4 Types over time
# -Total packets with Layer 5 Types over time
# -Total HTTP/HTTPS Requests made from source over time
# -Total DNS Queries made from source over time
# -Total ARP reqiests made from source over time


# Takes the provided DataFrame, 
def __GraphingTime(df, index, Title):
    global savepath
    sns.set()

    plt = df.set_index(index).T.plot(kind='bar', width=1, stacked=True, colormap='magma')
    
    plt.legend(loc='center left', bbox_to_anchor=(1,0.5), fontsize=7)

    plt.set_xlabel("Timestamp")
    plt.set_ylabel("Count")
    plt.tick_params(labelsize=7)

    plt.figure.savefig((savepath + "/" + Title), bbox_inches = "tight")
    plt.figure.clf()
    
# Reads the start and end of the capture, divides the total
# elapsed time into ten sections and returns the timestamp
# periods and an empty data array.
def __TS_Range(packets):
    data = []
    times = []
    ts = []

    for pkt in packets:
        times.append(float(pkt.time))
    times.sort()

    diff = float(times[-1]) - float(times[0])
    per = diff/10

    for i in range(1,11):
        stamp = float(times[0]) + (per * i)
        ts.append(stamp)

    return data, ts

    
# Analyzes the provided packets, calculates the ammount
# of packets from an IP source over a period of time and 
# generates a table and a graph displaying the data.
def __IPsrc_Time(packets):
    title = 'IP Sources over Time'
    dex = 'IP Source'
    filename = 'IPSource_OverTime.png'

    data, ts = __TS_Range(packets)

    for pkt in packets:
        found1 = False
        if IP in pkt:
            addr = pkt[IP].src
            found1 = True
        elif IPv6 in pkt:
            addr = pkt[IPv6].src
            found1 = True
        
        # If the IP type is found
        if found1 == True:
            # If the timestamp is within the timerange
            found2 = False
            for i in range(len(ts)):
                if float(pkt.time) <= float(ts[i]):
                    found2 = True
                    found3 = False
                    for j in range(len(data)):
                        if data[j][0] == addr:
                            found3 = True
                            data[j][i+1] += 1
                            break

                    # If the addr is not already in the list        
                    if found3 == False:
                        a = [addr,0,0,0,0,0,0,0,0,0,0]
                        a[i+1] += 1
                        data.append(a)
                    break

            if found2 == False:
                found3 = False
                for j in range(len(data)):
                    if data[j][0] == addr:
                        found3 = True
                        data[j][len(ts)-1] += 1
                        break

                # If the addr is not already in the list        
                if found3 == False:
                    a = [addr,0,0,0,0,0,0,0,0,0,1]
                    data.append(a)
                break


    timestamps = [dex]
    for i in range(10):
        timestamps.append(convert_ts(ts[i]))

    # Create a dataframe to use for graphing the data
    df = pd.DataFrame(columns=timestamps, data=data)

    print("\n" + title)
    print(tabulate(df, headers=timestamps, tablefmt='pretty'))

    # Sends the dataframe to __GraphingTime() to generate a png
    # graph.
    __GraphingTime(df, dex, filename)
    print("(" + filename + ")\n")

    #------------------------------------------------------------

# Analyzes the provided packets, calculates the ammount
# of packets sent to an IP over a period of time and 
# generates a table and a graph displaying the data.
def __IPdest_Time(packets):
    title = 'IP Destinations over Time'
    dex = 'IP Destination'
    filename = 'IPDest_OverTime.png'

    data, ts = __TS_Range(packets)

    for pkt in packets:
        found1 = False
        if IP in pkt:
            addr = pkt[IP].dst
            found1 = True
        elif IPv6 in pkt:
            addr = pkt[IPv6].dst
            found1 = True
        
        # If the IP type is found
        if found1 == True:
            # If the timestamp is within the timerange
            found2 = False
            for i in range(len(ts)):
                if float(pkt.time) <= float(ts[i]):
                    found2 = True
                    found3 = False
                    for j in range(len(data)):
                        if data[j][0] == addr:
                            found3 = True
                            data[j][i+1] += 1
                            break

                    # If the addr is not already in the list        
                    if found3 == False:
                        a = [addr,0,0,0,0,0,0,0,0,0,0]
                        a[i+1] += 1
                        data.append(a)
                    break

            if found2 == False:
                found3 = False
                for j in range(len(data)):
                    if data[j][0] == addr:
                        found3 = True
                        data[j][len(ts)-1] += 1
                        break

                # If the addr is not already in the list        
                if found3 == False:
                    a = [addr,0,0,0,0,0,0,0,0,0,1]
                    data.append(a)
                break

    
    timestamps = [dex]
    for i in range(10):
        timestamps.append(convert_ts(ts[i]))

    # Create a dataframe to use for graphing the data
    df = pd.DataFrame(columns=timestamps, data=data)

    print("\n" + title)
    print(tabulate(df, headers=timestamps, tablefmt='pretty'))

    # Sends the dataframe to __GraphingTime() to generate a png
    # graph.
    __GraphingTime(df, dex, filename)
    print("(" + filename + ")\n")

# Analyzes the provided packets, calculates the ammount
# of Layer 3 packet types over time and generates a table 
# and a graph displaying the data.
def __L3_Time(packets):
    title = 'Layer 3 Packets over Time'
    dex = 'L3 Types'
    filename = 'L3Type_OverTime.png'

    data, ts = __TS_Range(packets)

    for pkt in packets:
        found1 = False

        layers = __GetPktLayers(pkt)
        if len(layers) >= 2:
            L3 = layers[1]
            found1 = True
        
        # If the IP type is found
        if found1 == True:
            # If the timestamp is within the timerange
            found2 = False
            for i in range(len(ts)):
                if float(pkt.time) <= float(ts[i]):
                    found2 = True
                    found3 = False
                    for j in range(len(data)):
                        if data[j][0] == L3:
                            found3 = True
                            data[j][i+1] += 1
                            break

                    # If the addr is not already in the list        
                    if found3 == False:
                        a = [L3,0,0,0,0,0,0,0,0,0,0]
                        a[i+1] += 1
                        data.append(a)
                    break

            if found2 == False:
                found3 = False
                for j in range(len(data)):
                    if data[j][0] == L3:
                        found3 = True
                        data[j][len(ts)-1] += 1
                        break

                # If the addr is not already in the list        
                if found3 == False:
                    a = [L3,0,0,0,0,0,0,0,0,0,1]
                    data.append(a)
                break


    timestamps = [dex]
    for i in range(10):
        timestamps.append(convert_ts(ts[i]))
    
    # Create a dataframe to use for graphing the data
    df = pd.DataFrame(columns=timestamps, data=data)

    print("\n" + title)
    print(tabulate(df, headers=timestamps, tablefmt='pretty'))

    # Sends the dataframe to __GraphingTime() to generate a png
    # graph.
    __GraphingTime(df, dex, filename)
    print("(" + filename + ")\n")

# Analyzes the provided packets, calculates the ammount
# of Layer 4 packet types over time and generates a table 
# and a graph displaying the data.
def __L4_Time(packets):
    title = 'Layer 4 Packets over Time'
    dex = 'L4 Types'
    filename = 'L4Type_OverTime.png'

    data, ts = __TS_Range(packets)

    for pkt in packets:
        found1 = False

        layers = __GetPktLayers(pkt)
        if len(layers) >= 3:
            L4 = layers[2]
            found1 = True
        
        # If the IP type is found
        if found1 == True:
            # If the timestamp is within the timerange
            found2 = False
            for i in range(len(ts)):
                if float(pkt.time) <= float(ts[i]):
                    found2 = True
                    found3 = False
                    for j in range(len(data)):
                        if data[j][0] == L4:
                            found3 = True
                            data[j][i+1] += 1
                            break

                    # If the addr is not already in the list        
                    if found3 == False:
                        a = [L4,0,0,0,0,0,0,0,0,0,0]
                        a[i+1] += 1
                        data.append(a)
                    break

            if found2 == False:
                found3 = False
                for j in range(len(data)):
                    if data[j][0] == L4:
                        found3 = True
                        data[j][len(ts)-1] += 1
                        break

                # If the addr is not already in the list        
                if found3 == False:
                    a = [L4,0,0,0,0,0,0,0,0,0,1]
                    data.append(a)
                break


    timestamps = [dex]
    for i in range(10):
        timestamps.append(convert_ts(ts[i]))
    
    # Create a dataframe to use for graphing the data
    df = pd.DataFrame(columns=timestamps, data=data)

    print("\n" + title)
    print(tabulate(df, headers=timestamps, tablefmt='pretty'))

    # Sends the dataframe to __GraphingTime() to generate a png
    # graph.
    __GraphingTime(df, dex, filename)
    print("(" + filename + ")\n")

# Analyzes the provided packets, calculates the ammount
# of Layer 5 packet types over time and generates a table 
# and a graph displaying the data.
def __L5_Time(packets):
    title = 'Layer 5 Packets over Time'
    dex = 'L5 Types'
    filename = 'L5Type_OverTime.png'

    data, ts = __TS_Range(packets)

    for pkt in packets:
        found1 = False

        layers = __GetPktLayers(pkt)
        if len(layers) >= 4:
            L5 = layers[3]
            found1 = True
        
        # If the L5 type is found
        if found1 == True:
            # If the timestamp is within the timerange
            found2 = False
            for i in range(len(ts)):
                if float(pkt.time) <= float(ts[i]):
                    found2 = True
                    found3 = False
                    for j in range(len(data)):
                        if data[j][0] == L5:
                            found3 = True
                            data[j][i+1] += 1
                            break

                    # If the addr is not already in the list        
                    if found3 == False:
                        a = [L5,0,0,0,0,0,0,0,0,0,0]
                        a[i+1] += 1
                        data.append(a)
                    break

            if found2 == False:
                found3 = False
                for j in range(len(data)):
                    if data[j][0] == L5:
                        found3 = True
                        data[j][len(ts)-1] += 1
                        break

                # If the addr is not already in the list        
                if found3 == False:
                    a = [L5,0,0,0,0,0,0,0,0,0,1]
                    data.append(a)
                break


    timestamps = [dex]
    for i in range(10):
        timestamps.append(convert_ts(ts[i]))
    
    # Create a dataframe to use for graphing the data
    df = pd.DataFrame(columns=timestamps, data=data)

    print("\n" + title)
    print(tabulate(df, headers=timestamps, tablefmt='pretty'))

    # Sends the dataframe to __GraphingTime() to generate a png
    # graph.
    __GraphingTime(df, dex, filename)
    print("(" + filename + ")\n")

# Analyzes the provided packets, calculates the ammount
# of HTTP/HTTPS packet types over time and generates a table 
# and a graph displaying the data.
def __HTTP_Time(packets):
    title = 'HTTP/HTTPS Packets over Time'
    dex = 'HTTP-HTTPS'
    filename = 'HTTP-HTTPS_OverTime.png'

    data, ts = __TS_Range(packets)

    for pkt in packets:
        found1 = False

        if TCP in pkt and (str(pkt[TCP].dport) == "443" or str(pkt[TCP].sport) == "443"):
            if IP in pkt:
                dest = pkt[IP].dst
                http = "https:\n" + dest
                found1 = True
            elif IPv6 in pkt:
                dest = pkt[IPv6].dst
                http = "https:" + dest
                found1 = True

        elif pkt.haslayer(HTTPRequest):
            try:
                url = pkt[HTTPRequest].Host.decode() + pkt[HTTPRequest].Path.decode()
                http = url
                found1 = True
            except:
                pass

        
        # If the url is found
        if found1 == True:
            # If the timestamp is within the timerange
            found2 = False
            for i in range(len(ts)):
                if float(pkt.time) <= float(ts[i]):
                    found2 = True
                    found3 = False
                    for j in range(len(data)):
                        if data[j][0] == http:
                            found3 = True
                            data[j][i+1] += 1
                            break

                    # If the addr is not already in the list        
                    if found3 == False:
                        a = [http,0,0,0,0,0,0,0,0,0,0]
                        a[i+1] += 1
                        data.append(a)
                    break

            if found2 == False:
                found3 = False
                for j in range(len(data)):
                    if data[j][0] == http:
                        found3 = True
                        data[j][len(ts)-1] += 1
                        break

                # If the addr is not already in the list        
                if found3 == False:
                    a = [http,0,0,0,0,0,0,0,0,0,1]
                    data.append(a)
                break


    timestamps = [dex]
    for i in range(10):
        timestamps.append(convert_ts(ts[i]))
    
    # Create a dataframe to use for graphing the data
    df = pd.DataFrame(columns=timestamps, data=data)

    print("\n" + title)
    print(tabulate(df, headers=timestamps, tablefmt='pretty'))

    # Sends the dataframe to __GraphingTime() to generate a png
    # graph.
    __GraphingTime(df, dex, filename)
    print("(" + filename + ")\n")

# Analyzes the provided packets, calculates the ammount
# of DNS packets over time and generates a table and a 
# graph displaying the data.
def __DNS_Time(packets):
    title = 'DNS Packets over Time'
    dex = 'Names'
    filename = 'DNS_OverTime.png'

    data, ts = __TS_Range(packets)

    for pkt in packets:
        found1 = False

        if DNS in pkt:
            for x in range(pkt[DNS].ancount):
                DNSname = pkt[DNSRR][x].rdata
                found1 = True
        
        # If the L5 type is found
        if found1 == True:
            # If the timestamp is within the timerange
            found2 = False
            for i in range(len(ts)):
                if float(pkt.time) <= float(ts[i]):
                    found2 = True
                    found3 = False
                    for j in range(len(data)):
                        if data[j][0] == DNSname:
                            found3 = True
                            data[j][i+1] += 1
                            break

                    # If the addr is not already in the list        
                    if found3 == False:
                        a = [DNSname,0,0,0,0,0,0,0,0,0,0]
                        a[i+1] += 1
                        data.append(a)
                    break

            if found2 == False:
                found3 = False
                for j in range(len(data)):
                    if data[j][0] == DNSname:
                        found3 = True
                        data[j][len(ts)-1] += 1
                        break

                # If the addr is not already in the list        
                if found3 == False:
                    a = [DNSname,0,0,0,0,0,0,0,0,0,1]
                    data.append(a)
                break


    timestamps = [dex]
    for i in range(10):
        timestamps.append(convert_ts(ts[i]))
    
    # Create a dataframe to use for graphing the data
    df = pd.DataFrame(columns=timestamps, data=data)

    print("\n" + title)
    print(tabulate(df, headers=timestamps, tablefmt='pretty'))

    # Sends the dataframe to __GraphingTime() to generate a png
    # graph.
    __GraphingTime(df, dex, filename)
    print("(" + filename + ")\n")

# Analyzes the provided packets, calculates the ammount
# of ARP packets over time and generates a table and a 
# graph displaying the data.
def __ARP_Time(packets):
    title = 'ARP Packets over Time'
    dex = 'Source'
    filename = 'ARP_OverTime.png'

    data, ts = __TS_Range(packets)

    for pkt in packets:
        found1 = False

        if ARP in pkt:
            ARPs = pkt[ARP].psrc + '\n' +  pkt[Ether].src
            found1 = True
        
        # If the ARP name is found
        if found1 == True:
            # If the timestamp is within the timerange
            found2 = False
            for i in range(len(ts)):
                if float(pkt.time) <= float(ts[i]):
                    found2 = True
                    found3 = False
                    for j in range(len(data)):
                        if data[j][0] == ARPs:
                            found3 = True
                            data[j][i+1] += 1
                            break

                    # If the addr is not already in the list        
                    if found3 == False:
                        a = [ARPs,0,0,0,0,0,0,0,0,0,0]
                        a[i+1] += 1
                        data.append(a)
                    break

            if found2 == False:
                found3 = False
                for j in range(len(data)):
                    if data[j][0] == ARPs:
                        found3 = True
                        data[j][len(ts)-1] += 1
                        break

                # If the addr is not already in the list        
                if found3 == False:
                    a = [ARPs,0,0,0,0,0,0,0,0,0,1]
                    data.append(a)
                break


    timestamps = [dex]
    for i in range(10):
        timestamps.append(convert_ts(ts[i]))
    
    # Create a dataframe to use for graphing the data
    df = pd.DataFrame(columns=timestamps, data=data)

    print("\n" + title)
    print(tabulate(df, headers=timestamps, tablefmt='pretty'))

    # Sends the dataframe to __GraphingTime() to generate a png
    # graph.
    __GraphingTime(df, dex, filename)
    print("(" + filename + ")\n")
        

#----------------------------------[Main]--------------------------------------
def __Main():
    global savepath
    if len(sys.argv) > 1:
        # Where to find the PCAP file to analyze
        PCAP = sys.argv[1]

        # Verify that the provided PCAP file is valid
        if ispath(PCAP) == False:
            print("[*] Error: Unknown path")
            sys.exit()

        # Determining where to store the graphs
        # Split where to find the PCAP into path and file
        pathname, filename = os.path.split(PCAP)

        # Will save to the same path as the PCAP file
        savepath = pathname + "/"
        name = filename.replace(".pcap", '')
        g_exist = False


        # If the graphs folder already exists, then try to make
        # a folder to sort our different stats based on the filename
        if os.path.exists((savepath + name)):
            i = 1
            while os.path.exists((savepath + name + str(i))):
                i += 1
            savepath = (savepath + name + str(i))
            os.mkdir(savepath)
        else:
            savepath = savepath + name
            os.mkdir(savepath)

        os.system("sudo chmod -R a+rw " + savepath)
            
        if ispath(PCAP) == False:
            print("[*] Error: Unknown path")
            sys.exit()
  
    else:
        print("[*] Error: Missing PCAP")
        sys.exit()


    print("Save path: " + savepath)
    packets = __ReadPCAP(PCAP)
    __GetStats(packets)
    
    os.system("sudo chmod -R a+rw {}".format(savepath))


#-----------------------------------[Run]--------------------------------------
__Main()
#------------------------------------------------------------------------------