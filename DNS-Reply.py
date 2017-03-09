import socket

# QRPOSITION=2        #QR在数据包中的起始位置
QNAMEPOSITION=12    #QName在数据包中的起始位置

class Header:
    ID = 0
    QR = 0
    OPCODE = 0
    AA = 0
    TC = 0
    RD = 0
    RA = 0
    Z = 0
    RCODE = 0
    QDCODE = 0
    ANCODE = 0
    NSCODE = 0
    ARCODE = 0


class DNSReply:
    msg = ""
    addr = ("", 0)
    data=[]

    def __init__(self):
        self.sockRecv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sockRecv.bind(("localhost", 53))
        self.sockSend=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.getFileData("dnsrelay.txt")

    def getFileData(self,file): #读入数据
        with open(file) as input:
            self.data=[tuple(line.strip().split(' ')) for line in input.readlines() if line!="\n"]

    def run(self):
        while True:
            self.msg, self.addr = self.sockRecv.recvfrom(1024)
            print(self.msg, self.addr)
            self.handleRequest()

    def handleRequest(self):    #处理请求
        bits=self.byteTobit(self.msg[2])
        if bits[0]=='0' and bits[1:5]=='0000':  #QR及OPCODE均为0(查询报)
            QName,next=self.getQName()
            Qtype=self.byteTobit(self.msg[next])+self.byteTobit(self.msg[next+1])
            Qclass=self.byteTobit(self.msg[next+2])+self.byteTobit(self.msg[next+3])
            if Qtype=='0'*15+'1' and Qclass=='0'*15+'1':    #QTYPE=A,QCLASS=IN
                for (ip,domain) in self.data:
                    if domain==QName:
                        response=self.createResponse(ip)
                        self.sendData(self.sockRecv,response,self.addr)
                        break
                else:
                    self.dnsForward()

    def createResponse(self,ip):    #构造回复报文
        ip=ip.split('.')
        response=self.msg[:2]   #ID
        if ip==['0','0','0','0']:   #域名不存在
            response+=b'\x81\x83'   #RCODE:3
            response+=b'\x00\x01'   #QDCOUNT
            response+=b'\x00\x00'   #ANCOUNT
            response+=b'\x00\x00'   #NSCOUNT
            response+=b'\x00\x00'   #ARCOUNT
        else:
            response+=b'\x81\x80'
            response+=b'\x00\x01'   #QDCOUNT
            response+=b'\x00\x01'   #ANCOUNT
            response+=b'\x00\x00'   #NSCOUNT
            response+=b'\x00\x00'   #ARCOUNT
            response+=self.msg[12:]
            response+=b'\xC0\x0C'   #压缩算法,指向前面的QNAME
            response+=b'\x00\x01'   #TYPE:A
            response+=b'\x00\x01'   #CLASS:IN(1)
            response+=b'\x00\x00\x00\xA8'   #TTL:168
            response+=b'\x00\x04'   #RDLENGTH:4
            for i in range(4):
                response+=int(ip[i]).to_bytes(1,'little')

        return response

    def sendData(self,sock,data,addr):
        sock.sendto(data,addr)

    def dnsForward(self):
        dnsAddr=('10.3.9.4',53)
        self.sendData(self.sockSend,self.msg,dnsAddr)
        msg,addr=self.sockSend.recvfrom(1024)
        self.sendData(self.sockRecv,msg,self.addr)

    def byteTobit(self,byte):   #字节转成位
        bit=bin(byte)[2:]
        bit='0'*(8-len(bit))+bit
        return bit

    def getQName(self): #获得请求报文中的域名及QTYPE位置
        QName=''
        i=QNAMEPOSITION
        while self.msg[i]!=0:
            for j in range(1,self.msg[i]+1):
                QName+=chr(self.msg[i+j])
            QName+='.'
            i=i+self.msg[i]+1 #下一个labels

        return QName[:len(QName)-1],i+1 #去掉最后一个.


def main():
    dnsReply = DNSReply()
    dnsReply.run()


if __name__ == '__main__':
    main()
    #
    # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # sock.bind(("localhost", 53))
    #
    # while True:
    #         msg, addr = sock.recvfrom(1024)
    #         print(msg, addr)
    #         # print(msg[0])
    #         # print(msg[1])
    #         # print(msg[2])
