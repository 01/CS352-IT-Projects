# this pseudo-code shows an example strategy for implementing
# the CS 352 socket library

# Andrew Khazanovich
# Stephen Lenoiy

import socket as syssock
import binascii
import struct
import sys
from collections import namedtuple
import time
from Queue import *
from random import *
import math

# Constants that can be changed in later parts
sock352_timeout = 0.2
sock352PktSize = 5000

# Packet structure definition
sock352PktHdrData = '!BBBBHHLLQQLL'  #
udpPkt_hdr_data = struct.Struct(sock352PktHdrData)

header_len = struct.calcsize(sock352PktHdrData)


# Flag Definitions
SOCK352_SYN = 0x1
SOCK352_FIN = 0x2
SOCK352_ACK = 0x4
SOCK352_RESET = 0x8
SOCK352_HAS_OPT = 0xA0

# this init function is global to the class and
# defines the UDP ports all messages are sent
# and received from
def init(UDPportTx, UDPportRx):  # initialize your UDP socket here
    print ("Inside Global Init...........")
    global udpGlobalSocket
    udpGlobalSocket = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)

    if udpGlobalSocket is None:
        print "This Failed to Create Socket"
    else:
        print "Successful Creation of Global Socket"

    if UDPportTx < 1 or UDPportTx > 65535:
        UDPportTx = 27182

    if UDPportRx < 1 or UDPportRx > 65535:
        UDPportRx = 27182


class socket:
    #Defines the fields for a socket
    def __init__(self):
        print ("Inside library init")
        self.connections = []
        self.backlog = []
        self.connected = False
        self.last_acked = 0
        self.next_seq_num = 0
        self.next_ack_no = 0
        self.initial_seq_no = 0
        return

    def bind(self, address):
        print "Binding()"
        udpGlobalSocket.setsockopt(syssock.SOL_SOCKET, syssock.SO_REUSEADDR, 1)
        udpGlobalSocket.bind(address)
        return

        # Initializes the handshaking system for the protocol
    def connect(self, address):  # fill in your code here
        print "Connecting........"
        self.initial_seq_no = randint(0, (math.pow(2, 64) - 1))  # create a new sequence number
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

        while True:
            # We resend the packet if we have a timeout
            udpGlobalSocket.sendto(packed_syn_packet, address)
            print "Address: ", address
            try:
                udpGlobalSocket.settimeout(sock352_timeout)
                raw_packet, sender = udpGlobalSocket.recvfrom(sock352PktSize)
                print "Packet Recieved... Packed Header is: ", binascii.hexlify(raw_packet)
                print "Unpacked Header is: ", udpPkt_hdr_data.unpack(raw_packet)
                break
            except syssock.timeout:
                print "Socket Timed Out.... Resending Packet"
                time.sleep(5)
            finally:
                udpGlobalSocket.settimeout(None)

        recieved_packet_header = packetHeader(raw_packet[:40])#SIGNALED THAT THIS LINE IS UNREACHABLE
        print "Flags...recieved_packet_header.flags:", recieved_packet_header.flags
        print "Recieved ack_no: ", recieved_packet_header.ack_no

        # Check to make sure the recieved response is an SYN ACK
        if (recieved_packet_header.flags != 5 or
                    recieved_packet_header.ack_no != (syn_packet.header.sequence_no + 1)):
            print "Not proper SYN"
        else:
            self.connected= True
            self.connections.append(address)
            self.next_seq_num = recieved_packet_header.ack_no
            self.last_acked = recieved_packet_header.ack_no - 1
            print "Connected Successfullly"
        return

    def listen(self, backlog):
        self.listening = True
        # if self.backlog has something on list (will implement later parts of project)
        return

    # We set up the timeout for the socket, received the header packet and unpack its data. We then check the flags to see if it
    #is a syn packet, if it so we accept the connection and initialize a sequence number for the ack packet.
    #We then respond with a packed ack packet back to the sender
    def accept(self):
        print "********************************************"
        print "Inside Accept"
        while True:
            try:
                # This means we got a packet.
                udpGlobalSocket.settimeout(sock352_timeout)
                raw_packet, sender = udpGlobalSocket.recvfrom(sock352PktSize)
                print sender
                print "Packet Read During Accept"
                print "Packet Recieved... Packed Header is: ", binascii.hexlify(raw_packet)
                #print "Unpacked Header is: ", udpPkt_hdr_data.unpack(raw_packet)
                recieved_packet_header = packetHeader(raw_packet[:40])#SIGNALED THAT THIS LINE IS UNREACHABLE
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

        print "Accepted Connection"
        self.initial_seq_no = randint(0, (math.pow(2, 64) - 1))
        self.last_acked = recieved_packet_header.sequence_no + recieved_packet_header.payload_len - 1
        ack_packet = packet()
        ack_packet.header.flags = (SOCK352_ACK + SOCK352_SYN)
        print "Ack_Packet_Header: ", ack_packet.header.flags
        print "recieved seqnum: ", recieved_packet_header.sequence_no
        ack_packet.header.sequence_no = self.initial_seq_no
        ack_packet.header.ack_no = recieved_packet_header.sequence_no + 1
        print "Ack_No", ack_packet.header.ack_no
        packed_ack_packet = ack_packet.packPacket()
        bytesSent = udpGlobalSocket.sendto(packed_ack_packet, sender)
        print bytesSent

        client_sock = self
        client_sock.connections.append(sender)
        return (client_sock, sender)
    


    # Close the socket. All future operations on the socket object will fail. The remote end will receive no more data
    # and a FIN packet will be sent out signaling the connection is terminated
    def close(self):  # fill in your code here
        # send a FIN packet (flags with FIN bit set)
        # remove the connection from the list of connections

        FIN_packet = packet()
        FIN_packet.header.flags = SOCK352_FIN
        packed_FIN = FIN_packet.packPacket()
        udpGlobalSocket.sendto(packed_FIN, self.connections[0])
        self.connections = []
        self.backlog = []
        self.connected = False
        self.last_acked = 0
        self.next_seq_num = 0
        self.next_ack_no = 0
        self.initial_seq_no = 0
        return

    def listen(self):  # null code for part 1
        pass
        return
    # We accept a certain amount of bytes from the buffer that is provided and then we return the buffer back to the sender
    # so it knows to resend any bytes that were not transmitted
    def send(self, buffer):
        print "*******************************************"
        print "Inside Send Method..........."
        global sPort  # example using a variable global to the Python module
        bytessent = 0  # fill in your code here
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
        print "Sending packet"
        while True:
            # We resend the packet if we have a timeout
            bytesSent = udpGlobalSocket.sendto(packed_data_packet, self.connections[0])

            try:
                udpGlobalSocket.settimeout(sock352_timeout)
                raw_packet_header, sender = udpGlobalSocket.recvfrom(header_len)
                recieved_packet_header = packetHeader(raw_packet_header)
                print "SeqNum Sent: ", data_packet.header.sequence_no
                print "Ack Recieved: ", recieved_packet_header.ack_no
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

        self.next_seq_num = recieved_packet_header.ack_no #SIGNALED THAT THIS LINE IS UNREACHABLE
        self.last_acked = recieved_packet_header.ack_no - 1
        self.next_ack_no = recieved_packet_header.ack_no + 1

        print "Returning ", bytesSent
        return bytesSent - header_len

    # Recv() is used to handle receiving packets from the socket
    def recv(self, bytes_to_receive):
        print "In Recieve"
        print "bytes to recieve: ", bytes_to_receive
        while True:
            try:
                # This means we got a packet.
                udpGlobalSocket.settimeout(sock352_timeout)
                raw_packet, sender = udpGlobalSocket.recvfrom(5000)
                recieved_packet_header = packetHeader(raw_packet[:40])
                print "Packet Recieved... Packed Header is: ", binascii.hexlify(raw_packet[:40])
                print "Unpacked Header is: ", udpPkt_hdr_data.unpack(raw_packet[:40])
                if (recieved_packet_header.flags > 0):
                    print "Not data packet"
                    if (recieved_packet_header.flags == SOCK352_FIN):
                        udpGlobalsocket.close()
                        break;

                else:
                    break

            except syssock.timeout:
                print "Socket timed out recieving"

            finally:
                udpGlobalSocket.settimeout(None)

        self.next_seq_num = recieved_packet_header.ack_no#SIGNALED THAT THIS LINE IS UNREACHABLE
        self.last_acked = recieved_packet_header.ack_no - 1
        self.next_ack_no = recieved_packet_header.ack_no + 1

        # print "Payload length :", recieved_packet_header.payload_len

        payload = raw_packet[40: (40+bytes_to_receive)]
        print "payload length: ", len(payload)
        # as a 4 byte integer in network byte order (big endian)



        ack_packet = packet()
        ack_packet.create_ack(recieved_packet_header)
        print "Ack Packet Ack_NO: ", ack_packet.header.ack_no
        packed_ack_packet = ack_packet.packPacket()
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
        self.header.sequence_no = recievedHeader.ack_no + 1;
        self.header.flags = SOCK352_ACK;
    #Creates a SYN packet to signal a connection needs to be made
    def create_syn(self, seq_num):
        self.header.flags = SOCK352_SYN
        self.header.sequence_no = seq_num