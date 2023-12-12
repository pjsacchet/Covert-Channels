# Patrick Sacchet
# Covert Channels
# Dr. Lanier Watkins
# Homework 1

# This program will implement simple sender, receiver and firewall sides of method 1 as found in the paper "Covert Channels in the TCP/IP Protocol Suite" by C. Rowland
    # The sender functionality will take a specified target IP address and port number to connect to, and prompt the user for input to send a message over the wire
    # The receiver functionality will bind to the specified port and start listenting for a connection. It will accept any new connection and start decrypting package contents as they are sent
    # The firewall functionality will bind to the specified interface to start listening for traffic. As it receives packes, it will parse the IP identifaction field for suspicious values (ASCII values) and reject them as needed

import sys
import socket
import struct

# Import local stuff
import IP_HEADER
import TCP_HEADER

# Constants we use for... stuff...
SUCCESS = 0
FAILURE = -1
MAX_CONNECTIONS = 1
MIN_ARGS = 4
MAX_ARGS = 7
MIN_ASCII_VALUE = 33
MAX_ASCII_VALUE = 122
SEND_FUNCTION = 'send'
RECEIVE_FUNCTION = 'receive'
FIREWALL_FUNCTION = 'firewall'
EXIT = "exit"
PACKETS_TO_BE_SENT = []


# Computes the checksum for our TCP headers
# Params: data we want to compute the checksum of
# Return: checksum of data
def doChecksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s+= ord(data[i]) + (ord(data[i+1]) << 8)
    if n:
        s+= ord(data[i+1])
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff
    return s

# Prints help message for the user
# Params: None
# Return: success (0), failure (-1) otherwise
def printHelp():
    print(" In order to setup for sending data: ")
    print("         python3 SACCHET_PATRICK_Assignment_1.py send [SENDER_IP] [SENDER_PORT] [RECEIVER_IP] [RECEIVER_PORT]")
    print("         You will then be prompted for input data")
    print(" In order to setup for receiving data: ")
    print("         python SACCHET_PATRICK_Assignment_1.py receive [RECEIVER_IP] [RECEIVER_PORT]")
    print("         We will then listen on the specified port and continue parsing packets until user terminates program")
    print(" In order to setup firewall functionality: ")
    print("         python SACCHET_PATRICK_Assignment_1.py firewall [FIREWALL_IP] [FIREWALL_PORT] [RECEIVER_PORT]")
    print("         This assumes the user is running the firewall and the receiver on the same machine")
    return SUCCESS


# HConstructs an array of packets to send to the receiver
# Params: sender_ip - ip address of sender
#         sender_port - port number of sender
#         receiver_ip = ip address of receiver
#         receiver_port - port number of receiver
#         message - message the user wants to encode into the id field of the TCP header
# Return: success (0), failure (-1) otherwise
def constructPackets(sender_ip, sender_port, receiver_ip, receiver_port, message):
    packet = ''
    # Here we'll construct a packet for each letter in our message
        # There's a lot we dont update here but... for our purposes it works for now
    messageLength = len(message)
    i = 0
    while (i < messageLength):
        # Convert byte of our message to our ID field
        ip_id = ord(message[i])

        # Sender and receiver ips
        ip_saddr = socket.inet_aton(sender_ip)
        ip_daddr = socket.inet_aton(receiver_ip)

        # Construct IP header
        ip_header = struct.pack('!BBHHHBBH4s4s' , IP_HEADER.ip_ihl_ver, IP_HEADER.ip_tos, IP_HEADER.ip_tot_len, ip_id, IP_HEADER.ip_frag_off, IP_HEADER.ip_ttl, IP_HEADER.ip_proto, IP_HEADER.ip_check, ip_saddr, ip_daddr)

        # Construct TCP header... which takes a few steps since we need the correct checksum to insert prior to sending:
            # First we need the tcp header length
        tcp_header = struct.pack('!HHLLBBHHH' , int(sender_port), int(receiver_port), TCP_HEADER.tcp_seq, TCP_HEADER.tcp_ack_seq, TCP_HEADER.tcp_offset_res, TCP_HEADER.tcp_flags,  TCP_HEADER.tcp_window, TCP_HEADER.tcp_check, TCP_HEADER.tcp_urg_ptr)

         # Pseudo header field for length
        total_length = len(tcp_header) + len(TCP_HEADER.payload)
        # Pseudo header
        psh = struct.pack("!4s4sBBH", ip_saddr, ip_daddr, TCP_HEADER.tcp_reserv, TCP_HEADER.tcp_proto, total_length)
        #psh = psh + tcp_header + TCP_HEADER.payload
        # Current implementation does not send payload
        psh = psh + tcp_header
        tcp_checksum = doChecksum(str(psh))
        tcp_header = struct.pack("!HHLLBBH", int(sender_port), int(receiver_port), TCP_HEADER.tcp_seq, TCP_HEADER.tcp_ack_seq, TCP_HEADER.tcp_offset_res, TCP_HEADER.tcp_flags, TCP_HEADER.tcp_window)
        tcp_header += struct.pack('H', tcp_checksum) + struct.pack('!H', TCP_HEADER.tcp_urg)
        packet = ip_header + tcp_header
        # Add our packet to our array of packets
        PACKETS_TO_BE_SENT.append(packet)
        i+= 1

    return SUCCESS


# Handles the actual sending of data to our listener
# Params: sock - socket object being used for intialization
#         sender_ip - ip address of sender
#         sender_port - port number of sender
#         receiver_ip = ip address of receiver
#         receiver_port - port number of receiver
# Return: success (0), failure (-1) otherwise
def doSend(sock, sender_ip, sender_port, receiver_ip, receiver_port):
    try:
        print("Attempting to bind socket on " + str(sender_ip) + ":" + str(sender_port))
        sock.bind((sender_ip, int(sender_port)))
        print("Bound to socket! Sending packets to " + str(receiver_ip) + ":" + str(receiver_port))
        for packet in PACKETS_TO_BE_SENT:
            bytes_sent = sock.sendto(packet, (receiver_ip, int(receiver_port)))
            if (bytes_sent == 0 or bytes_sent == -1):
                print("Error when sending packets! ")
                return FAILURE

        # Successfully sent all our packets so go ahead and reset our array; otherwise we'll resend everything again next go around
        PACKETS_TO_BE_SENT.clear()

    except socket.error as message:
        print("Failed to send message to receiver! error code " + str(message))
        return FAILURE

    except KeyboardInterrupt:
        print("User terminated program; performing cleanup... ")
        status = doCleanup(sock)
        return status

    except:
        print("Something unexpected happened; attempting to cleanup... ")
        status = doCleanup(sock)
        return status

    return SUCCESS


# Handles setup for listening for our covert messages
# Params: sock - socket object being used for intialization
#         receiver_ip - ip address we'll bind to and wait for packets
#         receiver_port - port number we'll bind to and wait for packets
# Return: success (0), failure (-1) otherwise
def doReceive(sock, receiver_ip, receiver_port):
    try:
        print("Attempting to bind socket on " + str(receiver_ip) + ":" + str(receiver_port))
        sock.bind((receiver_ip, int(receiver_port)))
        print("Bound to socket! Server is listening... (ctrl+c to exit) ")
        while True:
            pkt, addr = sock.recvfrom(65565)
            print("Got packet from " + str(addr[0]) + " : " + str(chr(pkt[5])))

    except socket.error as message:
        print("Failed to bind for listening! error code " + str(message))
        return FAILURE

    except KeyboardInterrupt:
        print("User terminated program; performing cleanup... ")
        status = doCleanup(sock)
        return status

    except:
        print("Something unexpected happened; attempting to cleanup... ")
        status = doCleanup(sock)
        return status

    return SUCCESS


# Handles setup for listening for possibke malicious packets
# Params: sock - socket object being used for intialization
#         firewall_ip - ip address we'll bind to and wait for packets
#         firewall_port - port number we'll bind to and wait for packets
#         receiver_ip - ip address we will forward packets to if accepted
#         receiver_port - port number we will forward packets to if accepted
#         allow - boolean for mode setting; if true we dont perform check, otherwise we check for ID in packet prior to forwarding
# Return: success (0), failure (-1) otherwise
def doFirewall(sock, firewall_ip, firewall_port, firewall_send_port, receiver_ip, receiver_port):
    print("in start firewall")
    # Here we will act like a port forwarding service which accomplishes the same objectives as a firewall:
        # Intercept packets on port x, if the id field is a possible ASCII value (33 -122 are the values we are concerned with) then drop the packet
        # Otherwise, if the id field is outside of this range forward it to our listener on port y
    try:
        print("Attempting to bind socket on " + str(firewall_ip) + ":" + str(firewall_port))
        sock.bind((firewall_ip, int(firewall_port)))
        print("Bound to socket! Firewall is listening... (ctrl+c to exit) ")
        print("Also setting up send socket on  " + str(firewall_ip) + ":" + str(firewall_send_port))
        # Need separate socket on this machine for sending
        sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # This will break things since we dont change the 'sender' field when getting the packet
        #sendSock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sendSock.bind((firewall_ip, int(firewall_send_port)))
        print("Sending socket is bound! Ready to forward packets...")

        while True:
            pkt, addr = sock.recvfrom(65565)
            print("Looking at packet from " + str(addr[0]) + " : " + str(chr(pkt[5])))
            # If the ID field falls within our predetermined range then just forward the packet
                # Otherwise, we do nothing (packet is dropped)
            if (int(pkt[5]) < MIN_ASCII_VALUE or int(pkt[5]) > MAX_ASCII_VALUE):
                bytes_sent = sendSock.sendto(pkt, (receiver_ip, int(receiver_port)))
                if (bytes_sent == 0 or bytes_sent == -1):
                    print("Error when sending packets! ")
                    return FAILURE
                else:
                    print("Sent packet to " + str(receiver_ip) + ":" + str(receiver_port))

            else:
                print("Dropped packet from " + str(addr[0]))

    except socket.error as message:
        print("Failed to bind for listening! error code " + str(message))
        return FAILURE

    except KeyboardInterrupt:
        print("User terminated program; performin g cleanup... ")
        status = doCleanup(sock)
        return status

    except:
        print("Something unexpected happened; attempting to cleanup... ")
        status = doCleanup(sock)
        return status

    return SUCCESS


# Handles cleanup for any open sockets
# Params: sock - socket object being used for communications
# Return: success (0), failure (-1) otherwise
def doCleanup(sock):
    try:
        sock.close()

    except socket.error as message:
        print("Could not close socket! error code " + str(message))
        return FAILURE

    return SUCCESS


# Main functionality; will check for user flags for sending and receiving and initialize appropiately
# Params: None
# Return: Success (0), failure (-1) otherwise
def main():
    status = SUCCESS
    # Use RAW socket so we can construct stuff ourselves
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # This tells kernel not to put headers since we're making them... not needed with raw sockets but why not
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Check if user wants to send or receive data using aforementioned covert channel
    if (len(sys.argv) < MIN_ARGS or len(sys.argv) > MAX_ARGS):
        print("Invalid call of program: ")
        printHelp()
        return -1

    # User wants to send data
    elif(sys.argv[1] == SEND_FUNCTION):
        # First construct our packet(s) we're going to be sending
        user_message = ""
        while(user_message != EXIT):
            user_message = input("Please enter message for sending > ")
            if (user_message != EXIT):
                status = constructPackets(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], user_message)
                if (status != SUCCESS):
                    print("Construct packets failed, exiting... ")
                    return status

                # Now send the packets!
                status = doSend(sock, sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
                if (status != SUCCESS):
                    print("Send data failed, exiting... ")
                    return status

            else:
                print("User terminated program; performing cleanup... ")

    # User wants to receive data
    elif(sys.argv[1] == RECEIVE_FUNCTION):
        print("Binding to port specified to listen for incoming data... ")
        status = doReceive(sock, sys.argv[2], sys.argv[3])
        if (status != SUCCESS):
            print("Failed to bind to port for listening! :( exiting... ")
            return status

    # User wants to setup 'firewall'
    elif(sys.argv[1] == FIREWALL_FUNCTION):
        print("Binding to interface specified to listen for packets... ")
        status = doFirewall(sock, sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
        if (status != SUCCESS):
            print("Failed to bind to interface! :( eciting... ")
            return status

    # User didnt pass a valid flag
    else:
        print("Flag not recognized, please try again !")
        printHelp()
        return FAILURE


if __name__ == '__main__':
    main()
