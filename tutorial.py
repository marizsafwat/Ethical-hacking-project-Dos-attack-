from scapy.all import *
from datetime import datetime
from datetime import timedelta
import subprocess
dict1 = {}
dict2 = {}
dict3 = {}
dictArrivalTime = {}
def print_summary(pkt):
    #print(pkt)
    if IP in pkt:
       ip_src=pkt[IP].src
       ip_dst=pkt[IP].dst
    if UDP in pkt:
       UDP_sport=pkt[UDP].sport
       UDP_dport=pkt[UDP].dport
       
       print "IP src " +str(ip_src)+" UDP sport "+ str(UDP_sport)
       print "IP dst " +str(ip_dst)+" UDP dport "+ str(UDP_dport)
       
       if dict1.has_key(ip_src):
          dict1[ip_src]=dict1[ip_src]+1
          print "UDP DICTIONARY " + str(ip_src) + "  "+str(dict1[ip_src])
       else:
          dict1[ip_src]=1  
          print  "UDP DICTIONARY " + str(ip_src) +"  " +str(dict1[ip_src]) 
       
    if TCP in pkt:
       TCP_sport=pkt[TCP].sport
       TCP_dport=pkt[TCP].dport
       
       print "IP src " +str(ip_src)+" TCP sport "+ str(TCP_sport)
       print "IP dst " +str(ip_dst)+" TCP dport "+ str(TCP_dport) 
       
       if dict2.has_key(ip_src):
          dict2[ip_src]=dict2[ip_src]+1
          print "TCP DICTIONARY " + str(ip_src) + "  "+str(dict2[ip_src])
       else:
          dict2[ip_src]=1  
          print  "TCP DICTIONARY " + str(ip_src) +"  " +str(dict2[ip_src]) 
    
    if ICMP in pkt:  
       print "IP src " +str(ip_src) 
       print "IP dst " +str(ip_dst)
       #timenow=datetime.now()
       #if dict3.has_key(ip_src) :
           #print("difference"+str(timenow-dictArrivalTime[ip_src])+" "+str(dict3[ip_src]))
      
       if dict3.has_key(ip_src) and dict3[ip_src] >= 21 and (datetime.now() - dictArrivalTime[ip_src]) >= timedelta(0,20) and (datetime.now() - dictArrivalTime[ip_src]) < timedelta(0,35)and str(ip_src) != '192.168.1.13':
          dict3[ip_src]=-1
          subprocess.call(['iptables', '-A', 'INPUT', '-s', ip_src, '-j', 'DROP'])
          print "DOS ATTACK DETECTION AND BLOCKING SOURCE " + ip_src
       
       elif dict3.has_key(ip_src) and dict3[ip_src]>0 and dict3[ip_src] < 20 and (datetime.now() - dictArrivalTime[ip_src]) >= timedelta(0,20) and (datetime.now() - dictArrivalTime[ip_src]) < timedelta(0,35) and str(ip_src) != '192.168.1.13':
          #print ("HIIIIIII")
          dict3[ip_src]=1
          dictArrivalTime[ip_src]=datetime.now()
          
       elif dict3.has_key(ip_src) and dict3[ip_src]<0:
          subprocess.call(['iptables', '-A', 'INPUT', '-s', ip_src, '-j', 'DROP'])
          print "DOS ATTACK DETECTION AND BLOCKING SOURCE " + ip_src
          
       elif dict3.has_key(ip_src):
          dict3[ip_src]=dict3[ip_src]+1
          print "ICMP DICTIONARY " + str(ip_src) + "  "+str(dict3[ip_src])+" "+str(datetime.now()-dictArrivalTime[ip_src])
       else:
          dict3[ip_src]=1
          dictArrivalTime[ip_src]=datetime.now()
          print "ICMP DICTIONARY " + str(ip_src) + "  "+str(dict3[ip_src])+" "+str(dictArrivalTime[ip_src])
          
    
pkt=sniff(filter="ip",prn=print_summary)
