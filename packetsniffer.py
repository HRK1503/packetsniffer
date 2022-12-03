import collections
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import colors   
import collections
import argparse
from scapy.all import *
import time
import atexit

def graphshow(counter):
    print(counter)
    tim=[]
    for j in range(1,len(counter)+1):
        tim.append(j)
    print(tim)
    plt.bar(tim,counter)
    plt.xlabel("TIME")
    plt.ylabel("Number of packets")
    plt.show()
    


def get_args():
    parser=argparse.ArgumentParser()
    parser.add_argument('-i','--interface',type=str,required=True,help='name of network interface')
    parser.add_argument('-v','--verbose',default=False,action='store_true',help='print in detail')
    parser.add_argument('--count',type=int,default=0,help='number of packet to sniff, 0 is for indefinite')
    parser.add_argument('--filter',type=str,default="",help='to filter packets use BPF syntax')
    parser.add_argument('--store',type=str,default=0,help='to store captured packets')
    parser.add_argument('--graph',default=False,action='store_true',help='plot live graph')
    return parser.parse_args()

def printing(packet):
    global count
    global start_time
    global co
    global counter
    if args.store:
        wrpcap(args.store,packet,append=True)
    print("="*90,count,"="*90)
    count+=1
    if args.graph:
        if(time.time()-start_time>1):
            counter.append(co)
            co=0
            start_time=time.time()
        else:
            co=co+1  
    if args.verbose:
        packet.show()
    else:
        print(packet.summary())

def gr(counter):
    print(counter)           




count=1
start_time=time.time()
co=0
counter=[]
if __name__=="__main__":
	args=get_args()
	sniff(iface=args.interface,filter=args.filter ,count=args.count,prn=printing,store=args.store)
	if args.graph:
		atexit.register(graphshow(counter))
