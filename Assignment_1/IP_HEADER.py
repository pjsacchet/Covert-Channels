# Patrick Sacchet
# Covert Channels
# Dr. Lanier Watkins
# Homework 1

# We will use this file to define the constants for our IP header of the paclets we're constructing
import socket

source_ip = '127.0.0.1'
dest_ip = '192.168.75.1'

# IP header fields
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0	# Depending on what we're sending we'll figure this out later
ip_id = 54321	# Id of this packet... which we'll be manipulating...
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_check = 0	# We'll figure this out later
ip_saddr = socket.inet_aton ( source_ip )	# We could spoof this if we wanted
ip_daddr = socket.inet_aton ( dest_ip )

ip_ihl_ver = (ip_ver<< 4) + ip_ihl
