import collections
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.animation import FuncAnimation
import collections
import argparse
from scapy.all import *
import time

def my_function():
    # get data
    pac.popleft()
    pac.append(10)
    # clear axis
    ax.cla()
    # plot packet
    ax.plot(pac)
    plt.xlabel("Number of packets")
    plt.ylabel("Time")
    ax.scatter(len(pac)-1, pac[-1])
    ax.text(len(pac)-1, pac[-1]+2, "{}%".format(pac[-1]))
    ax.set_ylim(0,100)


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
    if args.store:
        wrpcap(args.store,packet,append=True)
    print("="*90,count,"="*90)
    count+=1
    if args.graph:
        pac= collections.deque(np.zeros(10))
        fig = plt.figure(figsize=(12,6), facecolor='#DEDEDE')
        ax = plt.subplot(121)
        ax.set_facecolor('#DEDEDE')
        ani = FuncAnimation(fig, my_function, interval=1000)
        plt.show()
    if args.verbose:
        packet.show()
    else:
        print(packet.summary())
        
    




count=1
if __name__=="__main__":
	args=get_args()
	sniff(iface=args.interface,filter=args.filter ,count=args.count,prn=printing,store=args.store)
