from socket import *
import os
import sys
import struct
import time
import select
import binascii

# represents type of ICMP packet
ICMP_ECHO_REQUEST = 8

def checksum(byteArray):
	csum = 0
	# round down size of byteArrayto nearest smaller or equal even number
	countTo = (len(byteArray) // 2) * 2
	count = 0
 
	# traverse the byteArray adding to the checksum
	while count < countTo:
		# combine two bytes from byteArray to form 16 bit unsigned int
		thisVal = byteArray[count+1] * 256 + byteArray[count]
		# add thisVal to the checksum
		csum = csum + thisVal
		# use bitwise & to restrict to 32 bit unsigned integer
		csum = csum & 0xffffffff
		# move to next pair of bytes in sequence
		count = count + 2
	
	# when byteArray is an odd number there is an additional byte to process
	if countTo < len(byteArray):
		# add value of last byte in byteArray to the checksum
		csum = csum + byteArray[len(byteArray) - 1]
		# make sure checksum remains 32 bit unsigned integer
		csum = csum & 0xffffffff
	
	# add high and low 16 bits of checksum together
	csum = (csum >> 16) + (csum & 0xffff)
	# ensures checksum is a 16 bit value
	csum = csum + (csum >> 16)
	# bitise NOT operator to get the inverse of checksum
	answer = ~csum
	# ensures answer is a 16 bit value
	answer = answer & 0xffff
	# swaps the higher 8 bits to the lower 8 bits and vice versa
	answer = answer >> 8 | (answer << 8 & 0xff00)

	return answer

def receiveOnePing(mySocket, ID, timeout, destAddr):
    # timeLeft gets set to 1 second initially
	timeLeft = timeout
 
	while 1:
		# store the current time
		startedSelect = time.time()
		# waits for socket to become readable (for pong to be available)
		whatReady = select.select([mySocket], [], [], timeLeft)
		# measures how long we waited in select operation (when did socket become readable)
		howLongInSelect = (time.time() - startedSelect)
  
		# A timeout occured
		if whatReady[0] == []:
			return "Request timed out."
		# records time when data is received
		timeReceived = time.time()
		# receives ICMP packet w/ max buffer size of 1024 bytes
		recPacket, addr = mySocket.recvfrom(1024)
  
		# Fetch the ICMP header from the IP packet
		# extracts header portion from the packet byte array
		header = recPacket[20:28]
		# unpacks the ICMP header giving all the info we want
		icmpType, code, checksum, packetID, sequence = struct.unpack("bbHHh", header) # bbHHh specifies data types and their order

        # Check if the received packet matches the expected packet ID
		if icmpType == 0 and packetID == ID: # type 0 means not an ICMP echo request
			# calculates size of a double
			bytesInDouble = struct.calcsize("d")
			# extract the time stamp from the received packet that was put in on packet send
			timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0] # time is a double stored 28 bytes into ICMP header
			# calculate the round trip time (rtt)
			rtt = timeReceived - timeSent
			return rtt
  
		# updates timeLeft before timeout
		timeLeft = timeLeft - howLongInSelect
  
		# Request timed out if more than 1 second elapses
		if timeLeft <= 0:
			return "Request timed out."

def sendOnePing(mySocket, destAddr, ID):
	# Header is type (8), code (8), checksum (16), id (16), sequence (16)
 
	myChecksum = 0
	# Make a dummy header with a 0 checksum
	# struct -- Interpret strings as packed binary data
	header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1) # bbHHh is string packing format being used
	# get current time and pack it into binary format using double precision
	data = struct.pack("d", time.time())
	# Calculate the checksum on the data and the dummy header.
	myChecksum = checksum(header + data)
 
	# Get the right checksum, and put in the header
	if sys.platform == 'darwin':
		# Convert 16-bit integers from host to network byte order to ensure consistent byte order over a network
		myChecksum = htons(myChecksum) & 0xffff
	else:
		myChecksum = htons(myChecksum)
  
	# now that we have checksum create the packet header and create the packet
	header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
	packet = header + data
 
	# send the packet across the socket to dest addr
	mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
	# Both LISTS and TUPLES consist of a number of objects
	# which can be referenced by their position number within the object.
 
def doOnePing(destAddr, timeout):
	icmp = getprotobyname("icmp") # IP protocol number 1
	# SOCK_RAW is a powerful socket type. For more details: http://sock-raw.org/papers/sock_raw
	# SOCK_RAW indicates the app will work with raw network packets (will have direct access to packet headers)
	# Raw sockets sometimes need admin priviledges to be used
	# AF_INET specifies the socket will use IPv4 addresses
	mySocket = socket(AF_INET, SOCK_RAW, icmp) # creates a raw socket to send and recieve ICMP packets
	# does bitwise AND with process id and 0xFFFF to restrict pid to 16 bits long
	myID = os.getpid() & 0xFFFF # Return the current process id
	# send a ping or a request to server
	sendOnePing(mySocket, destAddr, myID)
	# receive a pong or a response from server and capture the time it takes for a response
	delay = receiveOnePing(mySocket, myID, timeout, destAddr)
	mySocket.close()
	return delay

# host contains domain you want to look up
def ping(host, timeout=1):
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)  # does DNS resolution to get dest host IP
    print("Pinging " + dest + " using Python:")
    print("")
    
    # initialize some variables
    delays = []
    delay = None
    count = 0
    recPackets = 0
    delaySum = 0
    min = 1000
    max = -1000

    # Send ping requests to a server separated by approximately one second
    while count < 4:
        delay = doOnePing(dest, timeout)
        # add this delay to array
        delays.append(delay)
        count = count + 1
        
        # print the delay for each ping
        if delay is not None:
            message = "Ping num " + str(count) + ": " + str(delay) + " seconds"
            print(message)
        # wait one second for a response
        time.sleep(1)
    # loop through all ping delays
    for delay in delays:
        # when there is a delay
        if isinstance(delay, (int, float)):
            # increment received packets number and add the delay to the sum
            recPackets += 1
            delaySum += delay
            # find the min and max delay
            if delay > max:
                max = delay
            if delay < min:
                min = delay
        # no delay due to timed out
        elif delay == "Request timed out.":
            pass
    print("")
    # calculate packet loss percent 
    packetLoss = (1 - (recPackets/4)) * 100
    print("Packets transmitted: 4, Packets received: " + str(recPackets) + ", " + str(packetLoss) + "% packet loss")
    # calculate average delay
    avgDelay = (delaySum / recPackets)
    print("min/max/avg = " + str(min) + "/" + str(max) + "/" + str(avgDelay))
    print("")
    return

# google is domain being used here...
# ping("google.com")

print("Ping to LocalHost")
ping("127.0.0.1")

print('-----------------------')
print("Ping to Columbia")
ping("200.7.98.19")

print('-----------------------')
print("Ping to London, UK")
ping("185.158.241.176")

print('-----------------------')
print("Ping to China")
ping("www.china.org.cn") # China

print('-----------------------')
print("Ping to Australia")
ping("223.252.19.130") # Brisbane, Australia
