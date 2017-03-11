import socket
import select
import argparse
import threading
from threading import Lock
from concurrent.futures import ThreadPoolExecutor

QNAMEPOSITION=12    #QName在数据包中的起始位置

class DNSReply:
    requestIDs=[]   #请求报文中的ID
    transformIDs=[]  #转换后的ID
    data=[]

    def __init__(self,args):
        self.dnsServerIp=args.dnsServerIp
        self.sockRecv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sockRecv.bind(("localhost", 53))
        self.getFileData(args.dbFile)
        self.pool=ThreadPoolExecutor(4) #线程池
        self.lockSock=Lock()
        self.lockID=Lock()

    def getFileData(self,file): #读入数据
        with open(file) as input:
            self.data=[tuple(line.strip().split(' ')) for line in input.readlines() if line!="\n"]

    def run(self):
        while True:
            msg, addr = self.sockRecv.recvfrom(1024)
            print(msg, addr)
            self.pool.submit(self.handleRequest,msg,addr)

    def handleRequest(self,msg,addr):    #处理请求
        print(threading.current_thread().getName())
        bits=self.byteTobit(msg[2])
        if bits[0]=='0' and bits[1:5]=='0000':  #QR及OPCODE均为0(查询报)
            QName,next=self.getQName(msg)
            Qtype=self.byteTobit(msg[next])+self.byteTobit(msg[next+1])
            Qclass=self.byteTobit(msg[next+2])+self.byteTobit(msg[next+3])
            if Qtype=='0'*15+'1' and Qclass=='0'*15+'1':    #QTYPE=A,QCLASS=IN
                for (ip,domain) in self.data:
                    if domain==QName:
                        response=self.createResponse(msg,ip)
                        self.sockRecv.sendto(response,addr)
                        break
                else:
                    self.dnsForward(msg,addr)

    def createResponse(self,msg,ip):    #构造回复报文
        ip=ip.split('.')
        response=msg[:2]   #ID
        if ip==['0','0','0','0']:   #域名不存在
            response+=b'\x81\x83'   #RCODE:3
            response+=b'\x00\x01'   #QDCOUNT
            response+=b'\x00\x00'   #ANCOUNT
            response+=b'\x00\x00'   #NSCOUNT
            response+=b'\x00\x00'   #ARCOUNT
            response+=msg[12:]
        else:
            response+=b'\x81\x80'
            response+=b'\x00\x01'   #QDCOUNT
            response+=b'\x00\x01'   #ANCOUNT
            response+=b'\x00\x00'   #NSCOUNT
            response+=b'\x00\x00'   #ARCOUNT
            response+=msg[12:]
            response+=b'\xC0\x0C'   #压缩算法,指向前面的QNAME
            response+=b'\x00\x01'   #TYPE:A
            response+=b'\x00\x01'   #CLASS:IN(1)
            response+=b'\x00\x00\x00\xA8'   #TTL:168
            response+=b'\x00\x04'   #RDLENGTH:4
            for i in range(4):
                response+=int(ip[i]).to_bytes(1,'little')

        return response

    def dnsForward(self,msg,addr):
        with self.lockID:
            ID=self.byteTobit(msg[0])+self.byteTobit(msg[1])    #相同ID转换
            self.requestIDs.append(ID)
            while ID in self.transformIDs:
                ID=bin(int(ID,base=2)+1)[2:]    #ID+1
            self.transformIDs.append(ID)
            msg = int(ID, base=2).to_bytes(2, 'big')+msg[2:]  # ID

        dnsAddr=(self.dnsServerIp,53)
        msgRecv = None
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg, dnsAddr)  # 向远程DNS服务器发送请求
        ready = select.select([sock], [], [], 0.5)  # 0.5秒超时
        if ready[0]:
            msgRecv,addrRecv=sock.recvfrom(1024)
        # msgRecv=None
        # for i in range(3):  #未收到回复重发三遍
        #     sock.sendto(msg,dnsAddr)    #向远程DNS服务器发送请求
        #     ready=select.select([sock],[],[],0.5) #0.5秒超时
        #     if ready[0]:
        #         msgRecv,addrRecv=sock.recvfrom(1024)
        #     print(msgRecv)
        #     if msgRecv:
        #         break
        sock.close()
        with self.lockSock:
            with self.lockID:
                if msgRecv is None:
                    self.requestIDs.remove(self.requestIDs[self.transformIDs.index(ID)])  # 移除ID
                    self.transformIDs.remove(ID)
                else:
                    ID=self.byteTobit(msgRecv[0])+self.byteTobit(msgRecv[1])    #ID转换
                    ID=self.requestIDs[self.transformIDs.index(ID)]
                    msgRecv=int(ID,base=2).to_bytes(2,'big')+msgRecv[2:]
                    self.transformIDs.remove(self.transformIDs[self.requestIDs.index(ID)])   #移除ID
                    self.requestIDs.remove(ID)
                    self.sockRecv.sendto(msgRecv,addr)  #向请求方返回数据

    def byteTobit(self,byte):   #字节转成位
        bit=bin(byte)[2:]
        bit='0'*(8-len(bit))+bit
        return bit

    def getQName(self,msg): #获得请求报文中的域名及QTYPE位置
        QName=''
        i=QNAMEPOSITION
        while msg[i]!=0:
            for j in range(1,msg[i]+1):
                QName+=chr(msg[i+j])
            QName+='.'
            i=i+msg[i]+1 #下一个labels

        return QName[:len(QName)-1],i+1 #去掉最后一个.


def main():
    parse=argparse.ArgumentParser(description="This is a DNS relay.")
    parse.add_argument('-d',action="store_true",default=False,help="Debug level 1")
    parse.add_argument('-dd',action="store_true",default=False,help="Debug level 2")
    parse.add_argument(dest='dnsServerIp',action="store",nargs='?',default="10.3.9.6",help="DNS server ipaddr")
    parse.add_argument(dest='dbFile',action="store",nargs='?',default="./dnsrelay.txt",help="DB filename")
    args=parse.parse_args()
    print("NameServer:",args.dnsServerIp)
    print("DB file:",args.dbFile)
    print("Debug level:",2 if args.dd else (1 if args.d else 0))
    dnsReply = DNSReply(args)
    dnsReply.run()


if __name__ == '__main__':
    main()
