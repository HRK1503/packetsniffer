import argparse
from scapy.all import *

   
def get_args():
	parser=argparse.ArgumentParser()
	parser.add_argument('-i','--interface',type=str,required=True,help='name of network interface')
	parser.add_argument('-v','--verbose',default=False,action='store_true',help='print in detail')
	parser.add_argument('--count',type=int,default=0,help='number of packet to sniff, 0 is for indefinite')
	parser.add_argument('--filter',type=str,default="",help='to filter packets use BPF syntax')
	parser.add_argument('--store',type=str,default=0,help='to store captured packets')
	return parser.parse_args()
	
def printing(packet):
	global count
	if args.store:
		wrpcap(args.store,packet,append=True)
	print("="*100,count,"="*100)
	count+=1
	if args.verbose:
		packet.show()
	else:
		print(packet.summary())		

count=1
if __name__=="__main__":
	args=get_args()
	sniff(iface=args.interface,filter=args.filter ,count=args.count,prn=printing,store=args.store)
