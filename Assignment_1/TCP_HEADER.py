# Patrick Sacchet
# Covert Channels
# Dr. Lanier Watkins
# Homework 1

# We will use this file to define the constatns of the TCP header we're building
import socket

# TCP header fields
tcp_source = 1234	# Source port
tcp_dest = 80	# Destination port
tcp_seq = 0
tcp_ack_seq = 0
tcp_doff = 5	#4 bit field, size of tcp header, 5 * 4 = 20 bytes

#TCP flags
tcp_fin = 0
tcp_syn = 1
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_window = socket.htons (5840)	# Maximum allowed window size
tcp_check = 0
tcp_urg_ptr = 0

tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

payload = ''

# Pseudo header fields
tcp_reserv = 0
tcp_proto = socket.IPPROTO_TCP
