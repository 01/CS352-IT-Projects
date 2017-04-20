
# CS 352 project part 2 
# this is the initial socket library for project 2 
# You wil need to fill in the various methods in this
# library 
# coding=utf-8

# main libraries 
import binascii
import socket as syssock
import struct
import sys


# encryption libraries 
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box
import time
from random import *
import math

# Constants that can be changed in later parts
sock352_timeout = 0.2
sock352PktSize = 5000


# Packet structure definition
sock352PktHdrData = '!BBBBHHLLQQLL'
# Provides the proper format for a packet's header
udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
# Length of the packet header
header_len = struct.calcsize(sock352PktHdrData)


# Flag Definitions
SOCK352_SYN = 0x1
SOCK352_FIN = 0x2
SOCK352_ACK = 0x4
SOCK352_RESET = 0x8
SOCK352_HAS_OPT = 0xA0

# if you want to debug and print the current stack frame 
from inspect import currentframe, getframeinfo

# these are globals to the sock352 class and
# define the UDP ports all messages are sent
# and received from

# the public and private keychains in hex format 
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format 
global publicKeys
global privateKeys

# the encryption flag 
global ENCRYPT

# Hashmaps to store current connections and keys
publicKeysHex = {} 
privateKeysHex = {} 
publicKeys = {} 
privateKeys = {}
connections = {}

# this is 0xEC 
ENCRYPT = 236 

# this is the structure of the sock352 packet 
sock352HdrStructStr = '!BBBBHHLLQQLL'

def init(UDPportTx,UDPportRx):
    # Global variables that contain the sending and receiving port
    global send_port
    global recv_port

    # Setting the values for the global ports
    send_port = UDPportTx
    recv_port = UDPportRx

    # Creates the sockets to send and receive UDP packets on
    print (".....................Inside Global Init...........")
    global udpGlobalSocket
    udpGlobalSocket = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    udpGlobalSocket.setsockopt(syssock.SOL_SOCKET, syssock.SO_REUSEADDR, 1)

    # If the socket failed upon creation
    if udpGlobalSocket is None:
        print "This Failed to Create Socket"
    else:
        print "Successful Creation of Global Socket"


    # if the ports are not equal, create two sockets, one for Tx and one for Rx
    if int(UDPportTx) < 1 or int(UDPportTx) > 65535:
        send_port = '27182'

    if int(UDPportRx) < 1 or int(UDPportRx) > 65535:
        recv_port = '27182'

    # Binds the socket to a port
    print "Bind to RecvPort: ", int(recv_port)
    udpGlobalSocket.bind(('', int(recv_port)))
    

  
# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
    global publicKeysHex
    global privateKeysHex 
    global publicKeys
    global privateKeys 
    print "-------------------------Inside of readKeyChain file: %s------------------------" %filename

    # If the file name exists, scan the file line by line in search for the keys and ports
    if (filename):
        try:
            keyfile_fd = open(filename,"r")
            for line in keyfile_fd:
                words = line.split()
                #print line
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if ( (len(words) >= 4) and (words[0].find("#") == -1)):
                    host = words[1]
                    port = words[2]
                    keyInHex = words[3]
                    if (words[0] == "private"):
                        privateKeysHex[(host,port)] = keyInHex
                        privateKeys[(host,port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                    elif (words[0] == "public"):
                        publicKeysHex[(host,port)] = keyInHex
                        publicKeys[(host,port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
        except Exception,e:
            print ( "error: opening keychain file: %s %s" % (filename,repr(e)))
    else:
            print ("error: No filename presented")             

    return (publicKeys,privateKeys)

class socket:
    
    def __init__(self):
        # Initalizes the socket, setting all values to default
        print ("-------------------------Inside Library Init-----------------")
        self.connected = False
        self.last_acked = 0
        self.next_seq_num = 0
        self.next_ack_no = 0
        self.initial_seq_no = 0
        self.encrypt = False
        return
        
    def bind(self,address):
        # bind is not used in this assignment
        print "-------------------Binding()----------------"
        #udpGlobalSocket.setsockopt(syssock.SOL_SOCKET, syssock.SO_REUSEADDR, 1)
        #udpGlobalSocket.bind(address)
        return 

    def connect(self,*args):
        print "----------------Client is attempting to connect-------------------"
        # Global variables to see if messages will be encrypted, to access keys, and to access the global socket
        global ENCRYPT
        global publicKeysHex
        global privateKeysHex 
        global publicKeys
        global privateKeys
        global udpGlobalSocket 


        if (len(args) >= 1): 
            (host,port) = args[0]
            print ("Host: %s 	Port %s" %(host,port))

        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encrypt = True

        # Checks to see if the connection is encrypted
        if (self.encrypt == True):
            print "This Connection is Encrypted"
            print ("Connection's public key is: %s" % publicKeysHex[(host,recv_port)])
            print ("Private keys : %s" % privateKeysHex[('*', '*')])

        # Box for connecting/sending  boxForSend = Box(senderPrivate, recieverPrivate)
        self.box = Box(privateKeys[('*', '*')], publicKeys[(host,recv_port)])
        print ("Box created for Host: %s Port: %s" %(host,recv_port))

        # Creates the nonce
        self.nonce = nacl.utils.random(Box.NONCE_SIZE)

        #Generates a random initial sequence number and creates and packs a SYN packet
        self.initial_seq_no = randint(0, (math.pow(2, 64) - 1))
        print "Random Sequence Number Generate: %d" % self.initial_seq_no
        self.ack_number = 0
        print "Creating SYN Packet......."
        syn_packet = packet()
        syn_packet.create_syn(self.initial_seq_no)
        print "SYN Packet Created-Flag: %d SeqNum: %d" % (syn_packet.header.flags, syn_packet.header.sequence_no)
        print "Packing SYN Packet......."
        packed_syn_packet = syn_packet.packPacket()
        print "Length of header: %d" % len(packed_syn_packet)
        print "Packed Value   :", binascii.hexlify(packed_syn_packet)
        print "Sending SYN Packet....."

        # If the connection is encrypted, you must encrypt the packed synpacket and get the length of the
        # newly encrypted packet
        if(self.encrypt):
            packed_syn_packet = self.box.encrypt(packed_syn_packet, self.nonce)
            self.length_encrypted_header = len(packed_syn_packet)
            print "Length encrypted Header: ", len(packed_syn_packet)
            headerLen = self.length_encrypted_header

        while True:
            # We resend the packet if we have a timeout
            udpGlobalSocket.sendto(packed_syn_packet, (host, int(send_port)))
            #print "Address: ", (host, port)
            try:
                udpGlobalSocket.settimeout(sock352_timeout)
                raw_packet, sender = udpGlobalSocket.recvfrom(headerLen)	
                #print "Unpacked Header is: ", udpPkt_hdr_data.unpack(self.box.decrypt(raw_packet))
                break #test break
            except syssock.timeout:
                print "Socket Timed Out.... Resending Packet"
                time.sleep(5)
            finally:
                udpGlobalSocket.settimeout(None)

        #raw_packet = encrypted_packed_syn_packet #hardcoded
        if(self.encrypt):
            recieved_packet_header = packetHeader(self.box.decrypt(raw_packet))#SIGNALED THAT THIS LINE IS UNREACHABLE
        else:
            recieved_packet_header = packetHeader(raw_packet)
        print "Packet received... Packed Header is: ", recieved_packet_header
        print "Flags for recieved_packet_header.flags:", recieved_packet_header.flags
        print "received ACK_NO: ", recieved_packet_header.ack_no

        # Check to make sure the received response is an SYN ACK
        if (recieved_packet_header.flags != 5 or
                    recieved_packet_header.ack_no != (syn_packet.header.sequence_no + 1)):
            print "Not proper SYN"
        else:
            self.connected= True
            connections[sender] = sender
            self.destination = sender
            self.next_seq_num = recieved_packet_header.ack_no
            self.last_acked = recieved_packet_header.ack_no - 1
            print "Connected Successfullly"
        return


    def listen(self,backlog):
        # listen is not used in this assignments 
        self.listening = True
        return
    
    def accept(self,*args):
        global connections
        print "------------Server is accepting connections------------"
        global ENCRYPT

        # Checks to see if args length is > 1, if so it checks to if the server is encrypted
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encrypt = True
                print "This is Encrypted server"

        # If encrypted, the encrypted server creates the box
  
        # Loop used to receive packets and check encryption. Exception is made if timeout time is reached. If so it will try again.
        while True:
            try:
                # This means we got a packet.
                udpGlobalSocket.settimeout(sock352_timeout)
                raw_packet, sender = udpGlobalSocket.recvfrom(sock352PktSize)
                if(self.encrypt):
                    self.length_encrypted_header = len(raw_packet)
                    self.box = Box(privateKeys[('*', '*')], publicKeys[('localhost',send_port)])
                    raw_packet = self.box.decrypt(raw_packet)
                    print "Server PrivateKey: %s PublicKey: %s" %(privateKeysHex[('*', '*')], publicKeysHex[('localhost', recv_port)])
                    print "Encrypted Server Creating Box"
                print "Packet Read During Accept"
                print "Packet received... Packed Header is: ", binascii.hexlify(raw_packet)
                recieved_packet_header = packetHeader(raw_packet)
                # If statement to make sure the packet received is a SYN packet
                if (recieved_packet_header.flags != SOCK352_SYN):
                    print "Not Connection Request"
                else:
                    break
            except syssock.timeout:
                print "Socket timed out recieving"
                time.sleep(5)
                continue
            finally:
                udpGlobalSocket.settimeout(None)

        # Once we reach this point we have a connection. We then send back an ACK
        print "Accepted Connection"
        self.initial_seq_no = randint(0, (math.pow(2, 64) - 1))
        self.last_acked = recieved_packet_header.sequence_no + recieved_packet_header.payload_len - 1
        ack_packet = packet()
        if(connections.has_key(sender)):
            print "Server already connected to this client"
            ack_packet.header.flags = SOCK352_RESET
        else:        
		    ack_packet.header.flags = (SOCK352_ACK + SOCK352_SYN)
        print "Ack_Packet_Header: ", ack_packet.header.flags
        print "received seqnum: ", recieved_packet_header.sequence_no
        ack_packet.header.sequence_no = self.initial_seq_no
        ack_packet.header.ack_no = recieved_packet_header.sequence_no + 1
        print "Ack_No", ack_packet.header.ack_no
        packed_ack_packet = ack_packet.packPacket()
        # Checks to see if encrypted connection, if so must create nonce and encrpyt the ACK packet
        if(self.encrypt):
			self.nonce = nacl.utils.random(Box.NONCE_SIZE)
			packed_ack_packet = self.box.encrypt(packed_ack_packet, self.nonce)

        # Records the total number of bytes sent.
        bytesSent = udpGlobalSocket.sendto(packed_ack_packet, sender)
        self.destination = sender
        print bytesSent
        print "Sender: ", sender
        
        return (self, sender)


    def close(self):
        global connections

        # Creates the FIN packet for when close() is called
        FIN_packet = packet()
        FIN_packet.header.flags = SOCK352_FIN

        # Packs the FIN packet, if encryption we encrypt the FIN packet
        packed_FIN = FIN_packet.packPacket()
        if(self.encrypt):
             packed_FIN = self.box.encrypt(packed_FIN, self.nonce)

        # Send the FIN packet to the destination and reset the variables
        udpGlobalSocket.sendto(packed_FIN, self.destination)
        self.connected = False
        connections.pop(self.destination, None)
        self.destination = {}
        self.last_acked = 0
        self.next_seq_num = 0
        self.next_ack_no = 0
        self.initial_seq_no = 0
        return

    def send(self,buffer):
        print "*******************************************"
        print "Inside Send Method..........."
        global sPort  # example using a variable global to the Python module

        # The next six lines create the packet based on desired data
        payload = buffer[:4096]
        data_packet = packet()
        data_packet.header.payload_len = len(payload)
        data_packet.header.sequence_no = self.next_seq_num
        data_packet.header.ack_no = self.next_ack_no
        data_packet.payload = payload
        print "Length Payload: ", len(payload)

        packed_data_packet = data_packet.packPacket()
        print "Length of Data_Packet: ", len(packed_data_packet)
        # print "Packed Value   :", binascii.hexlify(packed_data_packet)

        #Encrypt packet if connection is encrypted
        print "Sending packet"
        if(self.encrypt):
            self.nonce = nacl.utils.random(Box.NONCE_SIZE)
            packed_data_packet = self.box.encrypt(packed_data_packet, self.nonce)

        # Attempts to send the packet. If timeout, it will resend. Like accept, if the timeout is hit
        # the exception will be thrown. There are also checks for the ACK number and flags to make sure it is a
        # proper ACK packet
        while True:
            # We resend the packet if we have a timeout
            bytesSent = udpGlobalSocket.sendto(packed_data_packet, self.destination)
            print "Bytes Sent: ", bytesSent

            try:
                udpGlobalSocket.settimeout(sock352_timeout)
                if(self.encrypt):
                    raw_packet_header, sender = udpGlobalSocket.recvfrom(self.length_encrypted_header)
                    raw_packet_header = self.box.decrypt(raw_packet_header)
                else:
                    raw_packet_header, sender = udpGlobalSocket.recvfrom(header_len)

                recieved_packet_header = packetHeader(raw_packet_header)
                print "SeqNum Sent: ", data_packet.header.sequence_no
                print "Ack received: ", recieved_packet_header.ack_no

                if (recieved_packet_header.flags != SOCK352_ACK or
                            recieved_packet_header.ack_no != (
                            data_packet.header.sequence_no + data_packet.header.payload_len)):
                    print "Not proper ACK"

                break

            except syssock.timeout:
                print "Socket Timed Out.... Resending Packet"
                continue

            finally:
                udpGlobalSocket.settimeout(None)

        # Stores the last ACK # and the next ACK #
        self.next_seq_num = recieved_packet_header.ack_no #SIGNALED THAT THIS LINE IS UNREACHABLE
        self.last_acked = recieved_packet_header.ack_no - 1
        self.next_ack_no = recieved_packet_header.ack_no + 1

        print "Returning ", bytesSent

        # Check to see if encrypted connection, if so must set length to encrypted header size
        if(self.encrypt):
             headerLen = self.length_encrypted_header
        else:
             headerLen = header_len

        bytesSent = len(buffer)

        if(len(buffer) > 4096):
            bytesSent = 4096

        
        return bytesSent

    def recv(self,nbytes):
        print "In Recieve"

        # Loop used to receive packet. Exception thrown if timeout. Also checks to see if it is a valid data packet
        # or if it is a FIIN packet
        while True:
            try:
                # This means we got a packet.
                udpGlobalSocket.settimeout(sock352_timeout)
                raw_packet, sender = udpGlobalSocket.recvfrom(5000)
                if(self.encrypt):
                    raw_packet = self.box.decrypt(raw_packet)
                
                recieved_packet_header = packetHeader(raw_packet[:header_len])
                print "Packet received... Packed Header is: ", binascii.hexlify(raw_packet[:header_len])
                print "Unpacked Header is: ", udpPkt_hdr_data.unpack(raw_packet[:header_len])

                if (recieved_packet_header.flags > 0):
                    print "Not data packet"
                    if (recieved_packet_header.flags == SOCK352_FIN):
                        udpGlobalSocket.close()
                       
                else:
                    break

            except syssock.timeout:
                print "Socket timed out recieving"

            finally:
                udpGlobalSocket.settimeout(None)

        self.next_seq_num = recieved_packet_header.ack_no#SIGNALED THAT THIS LINE IS UNREACHABLE
        # Stores the last ACK # and the next ACK num
        self.last_acked = recieved_packet_header.ack_no - 1
        self.next_ack_no = recieved_packet_header.ack_no + 1

        payload = raw_packet[(40): (40+nbytes)]
       
        print "payload length: ", len(payload)
        # as a 4 byte integer in network byte order (big endian)


        # Creates an ACK packet and checks to see if it needs to be encrypted. Packet is then sent to sender  
        ack_packet = packet()
        ack_packet.create_ack(recieved_packet_header)
        print "Ack Packet Ack_NO: ", ack_packet.header.ack_no
        packed_ack_packet = ack_packet.packPacket()
        if(self.encrypt):
            packed_ack_packet = self.box.encrypt(packed_ack_packet, self.nonce)
        udpGlobalSocket.sendto(packed_ack_packet, sender)

        return payload

 #Class is used just to simplify the code and use OOP. The following is a packet header object that contains
    #all of the parameters that a packet header require
class packetHeader:
    def __init__(self, rawHeader=None):
        self.header_struct = struct.Struct(sock352PktHdrData)

        if (rawHeader is None):
            self.flags = 0x0
            self.version = 0x1
            self.opt_ptr = 0x0
            self.protocol = 0x0
            self.checksum = 0x0
            self.sequence_no = 0x0
            self.source_port = 0x0
            self.ack_no = 0x0
            self.dest_port = 0x0
            self.window = 0x0
            self.payload_len = 0
        else:
            self.unpackHeader(rawHeader)

    #Returns a packed header object
    def packPacketHeader(self):
        return self.header_struct.pack(self.version, self.flags, self.opt_ptr, self.protocol,
                                       struct.calcsize(sock352PktHdrData),
                                       self.checksum, self.source_port, self.dest_port, self.sequence_no, self.ack_no,
                                       self.window, self.payload_len)
    #Returns an unpacked header where each field is stored as an array element
    def unpackHeader(self, rawUDPHeader):
        if len(rawUDPHeader) < 40:
            print ("Corrupt Packet, Invalid Header Data")
            return -1

        header_array = self.header_struct.unpack(rawUDPHeader)
        self.version = header_array[0]
        self.flags = header_array[1]
        self.opt_ptr = header_array[2]
        self.protocol = header_array[3]
        self.header_len = header_array[4]
        self.checksum = header_array[5]
        self.source_port = header_array[6]
        self.dest_port = header_array[7]
        self.sequence_no = header_array[8]
        self.ack_no = header_array[9]
        self.window = header_array[10]
        self.payload_len = header_array[11]
        return header_array

    #Creates a packet object that contains a header and payload of data
class packet:
    def __init__(self, header=None, payload=None):
        if header is None:
            self.header = packetHeader()
        else:
            self.header = header
        if payload is None:
            self.payload = None
        else:
            self.payload = payload
            self.header.payload_len = len(self.payload)
        pass
    #Packs the packetheader and payload as one object
    
    def packPacket(self):
        packed_header = self.header.packPacketHeader()

        if (self.payload is None):
            packed_packet = packed_header
        else:
            packed_packet = packed_header + self.payload

        return packed_packet

    #Creates an acknowledgement packet to signal the packet was received
    def create_ack(self, recievedHeader):
        self.header.ack_no = recievedHeader.sequence_no + recievedHeader.payload_len
        self.header.sequence_no = recievedHeader.ack_no + 1
        self.header.flags = SOCK352_ACK;
    #Creates a SYN packet to signal a connection needs to be made
    def create_syn(self, seq_num):
        self.header.flags = SOCK352_SYN
        self.header.sequence_no = seq_num    