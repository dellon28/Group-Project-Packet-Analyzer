#!/bin/python3

import math
import os
import random
import re
import sys

# Function to create a packet object
def makePacket(srcIP, dstIP, length, prt, sp, dp, sqn, pld):
    return ("PK", srcIP, dstIP, [length, prt, [sp, dp], sqn, pld])

# Functions to extract specific attributes from a packet
def getPacketSrc(pkt):
    return pkt[1]  # Extract the source IP

def getPacketDst(pkt):
    return pkt[2]  # Extract the destination IP

def getPacketDetails(pkt):
    return pkt[3]  # Extract all packet details

# Check if an object is a valid packet
def isPacket(pkt):
    return type(pkt) == tuple and pkt[0] == "PK" and len(pkt) == 4

# Check if a packet is empty
def isEmptyPkt(pkt):
    if isPacket(pkt):
        return getPacketDetails(pkt) == []
    else:
        raise TypeError("Must be a packet")

#-------------------Part 2: Access Packet Details---------------------------------
def getLength(pkt):
    return getPacketDetails(pkt)[0]  # Extract packet length

def getProtocol(pkt):
    return getPacketDetails(pkt)[1]  # Extract packet protocol

def getSrcPort(pkt):
    return getPacketDetails(pkt)[2][0]  # Extract source port

def getDstPort(pkt):
    return getPacketDetails(pkt)[2][1]  # Extract destination port

def getSqn(pkt):
    return getPacketDetails(pkt)[3]  # Extract sequence number

def getPayloadSize(pkt):
    return getPacketDetails(pkt)[4]  # Extract payload size

#------------------------Part 3: Analyze Packets---------------------------------

# Calculate the average payload size and return packets above the average
def flowAverage(packet_List):
    lstPack = []
    size = 0
    for pkt in packet_List:
        size += getPayloadSize(pkt)  # Sum up payload sizes
    average = size / len(packet_List)  # Calculate average payload size

    for pkt in packet_List:
        if getPayloadSize(pkt) > average:
            lstPack.append(pkt)  # Include packets above the average
    return lstPack

# Check if packet has suspicious source or destination ports
def suspPort(pkt):
    if getSrcPort(pkt) > 500 or getDstPort(pkt) > 500:
        return True
    return False

# Check if packet uses a suspicious protocol
def suspProto(pkt):
    NormList = ["HTTP", "SMTP", "UDP", "TCP", "DHCP"]
    if getProtocol(pkt) not in NormList:
        return True
    else:
        return False

# Check if the packet source IP is blacklisted
def ipBlacklist(pkt):
    BlackList = ["213.217.236.184", "149.88.83.47", "223.70.250.146", "169.51.6.136", "229.223.169.245"]
    if getPacketSrc(pkt) in BlackList:
        return True
    else:
        return False

#------------------------------Part 4: Calculate Scores--------------------------

# Calculate the suspicion score for a packet
def calScore(pkt):
    score = 0
    if ipBlacklist(pkt):  # Add points for blacklisted IPs
        score += 10
    if suspProto(pkt):  # Add points for suspicious protocols
        score += 2.74
    if suspPort(pkt):  # Add points for suspicious ports
        score += 1.45
    if pkt in flowAverage(lst):  # Add points for being above the average payload
        score += 3.56
    return score  # Return total score

# Create a "score" data structure for a list of packets
def makeScore(pkt_list):
    scorelist = []
    for pkt in pkt_list:
        scorelist += [(pkt, calScore(pkt))]
    return ['score', [scorelist]]

# Extract contents of a score object
def Slist_contents(ScoreList):
    print(ScoreList)
    return ScoreList[1][0]

# Add a packet and its score to the score list
def addPacket(ScoreList, pkt):
    score = calScore(pkt)
    return Slist_contents(ScoreList).append((pkt, score))

# Get packets classified as suspicious (score > 5)
def getSuspPkts(ScoreList):
    newlist = [pkt for pkt, score in Slist_contents(ScoreList) if score > 5.00]
    return newlist

# Get packets classified as regular (score <= 5)
def getRegulPkts(ScoreList):
    newlist = [pkt for pkt, score in Slist_contents(ScoreList) if score <= 5.00]
    return newlist

# Check if an object is a valid score structure
def isScore(ScoreList):
    return ScoreList[0] == 'score'

# Check if a score structure is empty
def isEmptyScore(ScoreList):
    if isScore:
        return ScoreList[1] == []
    else:
        raise TypeError("not a score list")

#---------------------Part 5: Packet Queue---------------------------------------

def makePacketQueue():
    return ('PQ', [])

def contentsQ(q):
    return q[1]

def addToPacketQ(pkt, q):
    if isPacketQ(q):
        contentsQ(q).append(pkt)
    else:
        raise TypeError("This is not a queue")

# Check if an object is a valid packet queue
def isPacketQ(q):
    return q[0] == "PQ" and type(q) == tuple and len(q) == 2

#--------------------Part 6: Packet Stack----------------------------------------

def makePacketStack():
    return ("PS", [])

def contentsStack(stk):
    return stk[1]

#--------------------Part 7: Sort Packets----------------------------------------

# Sort packets into queue and stack based on their score
def sortPackets(scoreList, stack, queue):
    keep = getRegulPkts(scoreList)
    discard = getSuspPkts(scoreList)
    for k in keep:
        addToPacketQ(k, queue)
    for d in discard:
        contentsStack(stack).append(d)

#----------------------Part 8: Main Driver Function------------------------------

def analysePackets(packet_List):
    pQueue = makePacketQueue()  # Create packet queue
    pStack = makePacketStack()  # Create packet stack

    # Convert raw packets into packet objects
    lst = [makePacket(*pkts) for pkts in packet_List]

    # Create a Score ADT using the formatted packet objects
    scoreList = makeScore(lst)

    # Sort packets into queue and stack
    sortPackets(scoreList, pStack, pQueue)

    # Sort the queue by sequence number in descending order
    contentsQ(pQueue).sort(key=lambda pkt: getSqn(pkt), reverse=False)

    return pQueue  # Return the sorted queue

#----------------------Part 9: Execute the Code----------------------------------

if __name__ == '__main__':
    fptr = open(os.environ['OUTPUT_PATH'], 'w')

    first_multiple_input = input().rstrip().split()
    
    srcIP = str(first_multiple_input[0])
    dstIP = str(first_multiple_input[1])
    length = int(first_multiple_input[2])
    prt = str(first_multiple_input[3])
    sp = int(first_multiple_input[4])
    dp = int(first_multiple_input[5])
    sqn = int(first_multiple_input[6])
    pld = int(first_multiple_input[7])
    
    # Define protocol and blacklist
    ProtocolList = ["HTTPS", "SMTP", "UDP", "TCP", "DHCP", "IRC"]
    IpBlackList = ["213.217.236.184", "149.88.83.47", "223.70.250.146", "169.51.6.136", "229.223.169.245"]
    
    # List of packets
    packet_List = [
        (srcIP, dstIP, length, prt, sp, dp, sqn, pld),
        ("111.202.230.44", "62.82.29.190", 31, "HTTP", 80, 20, 1562436, 338),
        ("222.57.155.164", "50.168.160.19", 22, "UDP", 790, 5431, 1662435, 812),
        ("333.230.18.207", "213.217.236.184", 56, "IMCP", 501, 5643, 1762434, 3138),
        ("444.221.232.94", "50.168.160.19", 1003, "TCP", 4657, 4875, 1962433, 428),
        ("555.221.232.94", "50.168.160.19", 236, "HTTP", 7753, 5724, 2062432, 48),
    ]
    
    # Analyze the packets and write the output
    fptr.write('Forward Packets => ' + str(analysePackets(packet_List)) + '\n')
    fptr.close()

    
    fptr.write('Forward Packets => ' + str(analysePackets(packet_List)) + '\n')
    
    fptr.close()
