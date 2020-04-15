#!/usr/bin/python3
#---------------------------------[Imports]------------------------------------
# Import modules
from collections import Counter, defaultdict
import datetime
from datetime import datetime, timedelta
import os
import pickle
import time
import subprocess
import sys

# Downloaded modules
from scapy.all import *
from scapy.all import sniff, AsyncSniffer
import scapy.all as scapy
from termcolor import colored, cprint

#---------------------------------[Globals]------------------------------------
global SetupComplete
global BaseComplete

#---------------------------------[Classes]------------------------------------
class BaseCap:
    # Initialize functu=ion used to load the base settings, create the 
    # capture files and start the capture
    def __init__(self):
        # Loads the pickle object for the base settings dictionary
        global basesettings
        basesettings = self.load_obj('settings')

        # Creates the log files
        pathfile = (basesettings['BaseCapPath'] + '/' + basesettings['BaseFileName'])

        # Checks to see if file already exists. If it does, it adds a number
        # to the end of the file name.
        if os.path.exists((pathfile + '.pcap')):
            i = 1
            while os.path.exists((pathfile + str(i) + '.pcap')):
                i += 1
            log_pcap = pathfile + str(i) + '.pcap'
        else:
            log_pcap = pathfile + '.pcap'
        
        # Creates the pcap file
        f = open(log_pcap, "a")
        f.close()

        basesettings.update({'LogPCAP': log_pcap})
        
        self.save_obj(basesettings, 'settings')

        self.__StartCap()
        
    # The startup function of the base capture.
    def __StartCap(self):
        global basesettings

        # Used to count how many packets have been recieved throughout capture
        global pkt_count
        pkt_count = 1
        
        # Determine if user specified a run time or a run period
        if basesettings['RunTime'] != '':
            # After calculating how long the program is specified to run for
            # the program starts an asynchronous sniffer that captures packets
            # in a seperate thread.
            dt_now, dt_run = self.__CalcRuntime()
            
            Asniff = AsyncSniffer(iface=basesettings['Interface'], prn=self.__DisplayPackets)
            Asniff.start()
            
            while dt_now <= dt_run:
                dt_now, str_now, date_now = self.__GetTimeNow()

            Asniff.stop()
            print(colored("\nScan has stopped!", 'green'))
        
        elif basesettings['RunPeriod'] != '':
            # After calculating how long the program is specified to run for
            # the program starts an asynchronous sniffer that captures packets
            # in a seperate thread.
            dt_now, dt_run = self.__CalcPeriod()

            Asniff = AsyncSniffer(iface=basesettings['Interface'], prn=self.__DisplayPackets)
            Asniff.start()
            
            while dt_now <= dt_run:
                dt_now, str_now, date_now = self.__GetTimeNow()

            Asniff.stop()
            print(colored("\nScan has stopped!", 'green'))

    # From the given Run Time, it calculates how long the program will run.
    # Run Time is used to specify a time of day that the program will run
    # for. Ex. from the time of scan start to 13:30. If the time specified has
    # passed before the scan has started, it will run until the run time of
    # the next day.
    def __CalcRuntime(self):
        global basesettings

        dt_now, time_now, date_now = self.__GetTimeNow()

        rt_hours, rt_minutes = self.__ConvertRunTime(basesettings['RunTime'])

        rt_time = dt_now.strftime("%Y-%m-%d %H:%M:%S")
        rt_time = datetime.strptime(rt_time, "%Y-%m-%d %H:%M:%S")

        rt_time = rt_time.replace(hour=rt_hours, minute=rt_minutes, second=0, microsecond=0)

        dt_run = rt_time

        if dt_run < dt_now:
                dt_run += timedelta(days=1)

        return dt_now, dt_run 

    # Converts the hh:mm format into hours and minutes
    def __ConvertRunTime(self, RunTime):
        rt = RunTime.split(':')
        hours = int(rt[0])
        minutes = int(rt[1])

        return hours, minutes

    # From the given Run Period, it calculates how long the program will run.
    # Run Period is used to specify how long they want the program to run for.
    # Ex. 1 hour and 30 minutes. It will take the current time and add on the 
    # time specified.
    def __CalcPeriod(self):
        global basesettings

        dt_now, time_now, date_now = self.__GetTimeNow()

        per_days, per_hours, per_minutes = self.__ConvertPeriod(basesettings['RunPeriod'])

        rt_time = dt_now.strftime("%Y-%m-%d %H:%M:%S")
        rt_time = datetime.strptime(rt_time, "%Y-%m-%d %H:%M:%S")
        rt_time += timedelta(days=per_days, hours=per_hours, minutes=per_minutes)
        dt_run = rt_time

        return dt_now, dt_run

    # Converts the d:h:m format into days, hours and minutes
    def __ConvertPeriod(self, RunPeriod):
        per = RunPeriod.split(':')
        days = int(per[0])
        hours = int(per[1])
        minutes = int(per[2])
        
        return days, hours, minutes

    # Gets the time now for runtime calculations
    def __GetTimeNow(self):
        now = datetime.now()
        current_day = datetime.today()
        current_time = now.strftime("%H:%M:%S")

        return now, current_time, current_day

    # Displays a summary of the packets onto command-line
    def __DisplayPackets(self, Packet):
        global pkt_count
        timestamp = self.__GetTime()
        pkts = Packet

        self.__LogPackets(pkts)

        pktsum = (colored((str(pkt_count) + ") "), 'yellow')) + (colored(str(timestamp), 'blue')) + Packet.summary()
        print(pktsum)

        pkt_count += 1

    # Logs the captured packets into a pcap file
    def __LogPackets(self, pkts):
        global basesettings

        log_pcap = (basesettings['BaseCapPath'] + '/' + basesettings['BaseFileName'] + '.pcap')
        wrpcap(log_pcap, pkts, append=True)

    # Used to load pickle files, such as the basesettings
    def load_obj(self, name):
        with open('obj/' + name + '.pkl', 'rb') as f:
            return pickle.load(f)

    # Saves dictionaries and the likes as pickle objects
    def save_obj(self, obj, name):
        with open('obj/'+ name + '.pkl', 'wb') as f:
            pickle.dump(obj, f)

    # Gets a parsed timestamp of the recieved packets
    def __GetTime(self):
        dt = datetime.now()
        time = dt.strftime("%Y-%m-%d (%H:%M:%S:%f) ")
        return time
    
    def __GetTimestamp(self):
        timestamp = time.time()
        return str(timestamp)


#------------------------------------------------------------------------------