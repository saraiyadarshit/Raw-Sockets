
#This program rawhttpget that takes a URL on the command line 
#and downloads the associated file.
#The program is implemented using a SOCK_RAW/IPPROTO_RAW socket,
#which means that the program builds the IP and TCP headers in each packet.


# importing the required libraries
from urllib2 import urlparse
import socket, sys
import random,urlparse
from struct import *

#initializing buffer to store the packets
buffer_packet = 65565
#Generate random port numbers
port_number=random.randint(0,65565)
#Storing the url which is passed as a parameter
url_parameter = sys.argv[1]
#defining a function to get the localIP of the host by pinging google.com
#and extracting the localIP from DNS
def ip_of_localhost() :
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    user = ''
    host_temp = 'google.com'
    try:
        sock.connect((host_temp, 9))
        user = sock.getsockname()[0]
    except socket.error:
        user = "Unknown IP"
    finally:
        del sock
    return str(user)

#Divides the url into single strings of distinct strings
split_url = urlparse.urlsplit(url_parameter)

empty_string = ""
#Extracts the path from the given url
hostname = split_url.netloc 
#storing sourceIP
src_ipaddr = ip_of_localhost()
#storing destinationIP
dest_ipaddr = socket.gethostbyname(urlparse.urlparse(url_parameter).hostname)

#Initializing variable to store the data
fp = " "
#if url does not include any path, create index.html
if split_url.path == empty_string :
    path_url = "/"
    fp = "index.html"
else :
    length_of_path = len(split_url.path)
    last_character = split_url.path[length_of_path-1]
#if url includes / in last, create index.html
    if last_character == "/" :
        path_url =  "/"
        fp = "index.html"
    else :
#else create normal filename
        path_url = split_url.path
        split_name = split_url.path.rsplit("/",1)
        fp = split_name[1]


#Initializing a list to store the data of all the packets
packet_dictionary = {}

# Function to calculate checksum
def csum(msg):
    sm = 0
  
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        wr = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        sm = sm + wr
   
    sm = (sm>>16) + (sm & 0xffff);
    sm = sm + (sm >> 16);
   
    #complement and mask to 4 byte short
    sm = ~sm & 0xffff
   
    return sm
  
#create a raw socket
try:
    send_sockraw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error , msg:
    print 'Raw Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
   
# Constructing the sending packet
sending_packet = '';
 

 
# ip header fields
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0  # kernel will fill the correct total length
ip_id = 54321   #Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_check = 0    # kernel will fill the correct checksum
ip_saddr = socket.inet_aton ( src_ipaddr )   #Spoof the source ip address if you want to
ip_daddr = socket.inet_aton ( dest_ipaddr )
 
ip_ihl_ver = (ip_ver << 4) + ip_ihl
 
# the ! in the pack format string means network order
ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
 
# tcp header fields
tcp_source = port_number  # source port
tcp_dest = 80   # destination port
tcp_seq = 0
tcp_ack_seq = 0
tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
#tcp flags
tcp_fin = 0
tcp_syn = 1
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_window = socket.htons (5)    #maximum allowed window size
tcp_check = 0
tcp_urg_ptr = 0
 
tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

# the ! in the pack format string means network order
tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
 
#Initializig request data 
request_data = ''
 
# pseudo header fields
addr_of_src = socket.inet_aton( src_ipaddr )
addr_of_dest = socket.inet_aton(dest_ipaddr)
placehold = 0
used_prtcl = socket.IPPROTO_TCP
length_of_tcp = len(tcp_header) + len(request_data)
 
#packing the packet
packet_maker = pack('!4s4sBBH' , addr_of_src , addr_of_dest , placehold , used_prtcl , length_of_tcp);
packet_maker = packet_maker + tcp_header + request_data;
 
tcp_check = csum(packet_maker)
 
# make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
 
# final full packet - syn packets dont have any data
sending_packet = ip_header + tcp_header + request_data
 
#Send the packet finally - the port specified has no effect
send_sockraw.sendto(sending_packet, (dest_ipaddr , 0 ))    # put this in a loop if you want to flood the target


#create an INET, STREAMing socket
 
# receive a packet

#starting an infinite loop
while True:
#opening a raw socket
    try:
        recv_sockraw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
  
    received_packet = recv_sockraw.recvfrom(buffer_packet)
   
    #packet string from tuple
    received_packet = received_packet[0]
   
    #take first 20 characters for the ip header
    ip_header = received_packet[0:20]
   
    #now unpack them
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
   
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
   
    iph_length = ihl * 4
   
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
   
    tcp_header = received_packet[iph_length:iph_length+20]
   
    #now unpack them
    tcph = unpack('!HHLLBBHHH' , tcp_header)
   
    src_port = tcph[0]
    dest_port = tcph[1]
    seq_number = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
   
   
    h_size = iph_length + tcph_length * 4
    data_size = len(received_packet) - h_size
   
    #get data from the packet
    data = received_packet[h_size:]
    if s_addr == dest_ipaddr and d_addr == src_ipaddr and tcph[5] == 18 and port_number == tcph[1]:
       
    

  
    #send a acknowledgement
    # tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
    # s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
       
    # now start constructing the acknowledgement packet
        acknowledgement_packet = '';
              
        # ip header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  # kernel will fill the correct total length
        ip_id = 54322   #Id of this packet
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0    # kernel will fill the correct checksum
        ip_saddr = socket.inet_aton ( src_ipaddr )   #Spoof the source ip address if you want to
        ip_daddr = socket.inet_aton ( dest_ipaddr )
       
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
       
        # the ! in the pack format string means network order
        ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
       
        # tcp header fields
        tcp_source = port_number  # source port
        tcp_dest = 80   # destination port
        tcp_seq = tcph[3]
        tcp_ack_seq = tcph[2] + 1
        tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
        #tcp flags
        tcp_fin = 0
        tcp_syn = 0
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 1
        tcp_urg = 0
        tcp_window = socket.htons (5)    #   maximum allowed window size
        tcp_check = 0
        tcp_urg_ptr = 0
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
       
        # the ! in the pack format string means network order
        tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
       

        data_for_ack = ''
       
        # pseudo header fields
        addr_of_src = socket.inet_aton( src_ipaddr )
        addr_of_dest = socket.inet_aton(dest_ipaddr)
        placehold = 0
        used_prtcl = socket.IPPROTO_TCP
        length_of_tcp = len(tcp_header) + len(data_for_ack)
       
        packet_maker = pack('!4s4sBBH' , addr_of_src , addr_of_dest , placehold , used_prtcl , length_of_tcp);
        packet_maker = packet_maker + tcp_header + data_for_ack;
       
        tcp_check = csum(packet_maker)
        #print tcp_checksum
       
        # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
        tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
       
        # final full packet - syn packets dont have any data
        acknowledgement_packet = ip_header + tcp_header + data_for_ack
        try:
            sendack_sockraw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
        sendack_sockraw.sendto(acknowledgement_packet, (dest_ipaddr , 0 ))    # put this in a loop if you want to flood the target
        break
  

#send a HTTP Get

try:
    sendhttp_sockraw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
# tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
   
# now start constructing the packet
httprequest_packet = '';
 
#src_ipaddr = '192.168.203.129'
#dest_ipaddr = '129.10.116.81' # or socket.gethostbyname('www.google.com')
 
# ip header fields
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0  # kernel will fill the correct total length
ip_id = 54323   #Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_check = 0    # kernel will fill the correct checksum
ip_saddr = socket.inet_aton ( src_ipaddr )   #Spoof the source ip address if you want to
ip_daddr = socket.inet_aton ( dest_ipaddr )
 
ip_ihl_ver = (ip_ver << 4) + ip_ihl
 
# the ! in the pack format string means network order
ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
 
# tcp header fields
tcp_source = port_number  # source port
tcp_dest = 80   # destination port
tcp_seq = tcph[3]
tcp_ack_seq = tcph[2] + 1
tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
#tcp flags
tcp_fin = 0
tcp_syn = 0
tcp_rst = 0
tcp_psh = 1
tcp_ack = 1
tcp_urg = 0
tcp_window = socket.htons (5)    #   maximum allowed window size
tcp_check = 0
tcp_urg_ptr = 0
 
tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
 
# the ! in the pack format string means network order
tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

request_httpdata = 'GET '+path_url+' HTTP/1.1\r\nHOST: '+hostname+'\r\n\r\n'

if len(request_httpdata) % 2 != 0:
    request_httpdata = request_httpdata + " "

# pseudo header fields
addr_of_src = socket.inet_aton( src_ipaddr )
dst_address = socket.inet_aton(dest_ipaddr)
placehold = 0
used_prtcl = socket.IPPROTO_TCP
length_of_tcp = len(tcp_header) + len(request_httpdata)
 
packet_maker = pack('!4s4sBBH' , addr_of_src , addr_of_dest , placehold , used_prtcl , length_of_tcp);
packet_maker = packet_maker + tcp_header + request_httpdata;
 
tcp_check = csum(packet_maker)
#print tcp_checksum
 
# make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
 
# final full packet - syn packets dont have any data
httprequest_packet = ip_header + tcp_header + request_httpdata
 
#Send the packet finally - the port specified has no effect
sendhttp_sockraw.sendto(httprequest_packet, (dest_ipaddr , 0 ))    # put this in a loop if you want to flood the target


#receive data html

#create an INET, STREAMing socket
try:
    recv_sockraw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

while True:
#receiving packet from the server
    received_packet = recv_sockraw.recvfrom(buffer_packet)
   
    #packet string from tuple
    received_packet = received_packet[0]
   
    #take first 20 characters for the ip header
    ip_header = received_packet[0:20]
   
    #unpacking the packet
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
   
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
   
    iph_length = ihl * 4
   
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
    tcp_header = received_packet[iph_length:iph_length+20]
    #unpacking the packet
    tcph = unpack('!HHLLBBHHH' , tcp_header)
      
    src_port = tcph[0]
    dest_port = tcph[1]
    seq_number = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    flags = tcph[5]
    
   
    h_size = iph_length + tcph_length * 4
    data_size = len(received_packet) - h_size
    if dest_port == port_number and s_addr == dest_ipaddr and data_size > 0:
       
        #get data from the packet
        data = received_packet[h_size:]
      
      #storing the sequence of packets
        packet_dictionary[seq_number] = data
      
      #packet for teardown initiation
        teardown_initiator = ''
   
       
   
        # ip header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  # kernel will fill the correct total length
        ip_id = 54322   #Id of this packet
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0    # kernel will fill the correct checksum
        ip_saddr = socket.inet_aton ( src_ipaddr )   #Spoof the source ip address if you want to
        ip_daddr = socket.inet_aton ( dest_ipaddr )
   
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
   
        # the ! in the pack format string means network order
        ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
   
        # tcp header fields
        tcp_source = port_number  # source port
        tcp_dest = 80   # destination port
        tcp_seq =  tcph[3]
        tcp_ack_seq = seq_number + data_size
        tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
        #tcp flags
        tcp_fin = 0
        tcp_syn = 0
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 1
        tcp_urg = 0
        tcp_window = socket.htons (5)    #   maximum allowed window size
        tcp_check = 0
        tcp_urg_ptr = 0
       
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
        #tcp_flags = 16
        # the ! in the pack format string means network order
        tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
       
#data to be sent during tear down
        data_for_teardown = ''
       
        # pseudo header fields
        addr_of_src = socket.inet_aton( src_ipaddr )
        addr_of_dest = socket.inet_aton(dest_ipaddr)
        placehold = 0
        used_prtcl = socket.IPPROTO_TCP
        length_of_tcp = len(tcp_header) + len(data_for_teardown)
       
        packet_maker = pack('!4s4sBBH' , addr_of_src , addr_of_dest , placehold , used_prtcl , length_of_tcp);
        packet_maker = packet_maker + tcp_header + data_for_teardown;
       
        tcp_check = csum(packet_maker)
       
   
        # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
        tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
   
        # final full packet - syn packets dont have any data
        teardown_initiator = ip_header + tcp_header + data_for_teardown
        try:
            ackall_sockraw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
        ackall_sockraw.sendto(teardown_initiator, (dest_ipaddr , 0 ))

    if (tcph[5] == 17 or tcph[5] == 25) and dest_port == port_number and s_addr == dest_ipaddr and data_size == 0:
        #finish the connection
#data to be sent during finishing the connection
        fin_packet = ''
   
       
   
        # ip header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  # kernel will fill the correct total length
        ip_id = 54322   #Id of this packet
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0    # kernel will fill the correct checksum
        ip_saddr = socket.inet_aton ( src_ipaddr )   #Spoof the source ip address if you want to
        ip_daddr = socket.inet_aton ( dest_ipaddr )
   
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
   
        # the ! in the pack format string means network order
        ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
   
        # tcp header fields
        tcp_source = port_number  # source port
        tcp_dest = 80   # destination port
        tcp_seq =  tcph[3]
        tcp_ack_seq = seq_number + 1
        tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
        #tcp flags
        tcp_fin = 1
        tcp_syn = 0
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 1
        tcp_urg = 0
        tcp_window = socket.htons (5)    #   maximum allowed window size
        tcp_check = 0
        tcp_urg_ptr = 0
       
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
        
        # the ! in the pack format string means network order
        tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
       #data to be sent in final packet
        data_in_finpacket = ''
       
        # pseudo header fields
        addr_of_src = socket.inet_aton( src_ipaddr )
        addr_of_dest = socket.inet_aton(dest_ipaddr)
        placehold = 0
        used_prtcl = socket.IPPROTO_TCP
        length_of_tcp = len(tcp_header) + len(data_in_finpacket)
       
        packet_maker = pack('!4s4sBBH' , addr_of_src , addr_of_dest , placehold , used_prtcl , length_of_tcp);
        packet_maker = packet_maker + tcp_header + data_in_finpacket;
       
        tcp_check = csum(packet_maker)
   
        # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
        tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
   
        # final full packet - syn packets dont have any data
        fin_packet = ip_header + tcp_header + data_in_finpacket
        try:
            sendfin_sockraw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
        sendfin_sockraw.sendto(fin_packet, (dest_ipaddr , 0 ))
        break
      

proper_sequence = sorted(packet_dictionary.iterkeys())
writefile = open (fp, "w")
counter = 0
for seq in proper_sequence:
    if counter == 0:
        str = packet_dictionary[seq]
        writefile.writelines(str.split('\r\n\r\n')[1])
        
        #inside the file function
        counter = counter + 1
    else:
        writefile.writelines(packet_dictionary[seq])   
    #writing into the files

