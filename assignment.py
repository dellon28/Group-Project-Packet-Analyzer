#!/bin/python3

import math
import os
import random
import re
import sys

def makePacket(srcIP, dstIP, length, prt, sp, dp, sqn, pld):
    return ("PK",srcIP,dstIP,[length,prt,[sp,dp],sqn,pld])
    
    
def getPacketSrc(pkt):
    return pkt[1]
    
    
def getPacketDst(pkt):
    return pkt[2]
   
    
def getPacketDetails(pkt):
    return pkt[3]
    
    
def isPacket(pkt):
    return type(pkt)==type(()) and pkt[0]=="PK" and len(pkt)==4
    
    
    

def isEmptyPkt(pkt):
    if isPacket(pkt):
        return getPacketDetails(pkt)==[]
    else:
        raise TypeError ("Must be a packet")
    
#-------------------Part 2--------------------------------------------------------------------
def getLength(pkt):
    return getPacketDetails(pkt)[0]
    
   
def getProtocol(pkt):
    return getPacketDetails(pkt)[1]
   

def getSrcPort(pkt):
    return getPacketDetails(pkt)[2][0]
   

def getDstPort(pkt):
    return getPacketDetails(pkt)[2][1]
   

def getSqn(pkt):
    return getPacketDetails(pkt)[3]
    

def getPayloadSize(pkt):
    return getPacketDetails(pkt)[4]

#------------------------Part 3----------------------------------------

def flowAverage(pkt_list):#This metric will accept a list of packets and gets the average payload size
#of all the packets. It will return a list of packets that are above the average of the list.
    lstPack=[]
    size=0
    for pkt in pkt_list:
        size+=getPayloadSize(pkt)
    average=size/len(pkt_list)
    
    for pkt in pkt_list:
        if getPayloadSize(pkt)>average:
            lstPack.append(pkt)
    return lstPack
        
        
        

def suspPort(pkt):
    if getSrcPort(pkt)>500 or getDstPort(pkt) >500:
        return True
    return False
   

def suspProto(pkt):
    NormList=["HTTP","SMTP","UDP","TCP","DHCP"]
    if getProtocol(pkt) not in NormList:
        return True
    else: 
        return False
   

def ipBlacklist(pkt):
    BlackList=["213.217.236.184","444.222.232.94","149.88.83.47","223.70.250.146","169.51.6.136","229.223.169.245"]
    if getPacketSrc(pkt) in BlackList:
        return True
    else: 
        return False


#--------------------------------------------------------------part 4---------------------------------------------------------------------------------------
def calScore(pkt):
    score=0 
    if ipBlacklist(pkt):
        score+= 10 
    if suspProto(pkt):
        score+=2.74
    if suspPort(pkt):
        score+=1.45
    if pkt in flowAverage(pkt_list):
        score+=3.56 
    return score
 
        
def makeScore(pkt_list):
    scorelist=[]
    for pkt in pkt_list:
        scorelist+= [(pkt,calScore(pkt))]
    return ['score',[scorelist]]
 

def addPacket(ScoreList, pkt):
    score=calScore(pkt)
    return ScoreList[1][0].append((pkt,score))
  

def getSuspPkts(ScoreList):
    newlist=[pkt for pkt,score in ScoreList[1][0] if score >5.00]
    return newlist


def getRegulPkts(ScoreList):#Takes a Score as an input and returns a list of all regular packets.
    newlist=[pkt for pkt,score in ScoreList[1][0] if score<=5.00]
    return newlist
 
            
def isScore(ScoreList):#Checks to see if a given list, is a valid Score.
    return ScoreList[0]=='score'
  
def isEmptyScore(ScoreList):
    if isScore:
        return ScoreList[1]==[]
    else:
        raise TypeError ("not a score list")


#-----------------------------------------------------part 5------------------------------------------------------------------------------------------------------
def makePacketQueue():
    return ('PQ',[])


def contentsQ(q):
    return q[1]
  

def frontPacketQ(q):
    if isEmptPacketQ(q):
        return contentsQ(q)[0]
    raise TypeError ("not a queue")
  

def addToPacketQ(pkt,q):
    if isPacketQ(q):
        pos=get_pos(pkt,contentsQ(q))
        contentsQ(q).insert(pos,pkt)
    else:
        raise TypeError("This is not a queue")
 

def get_pos(pkt,lst):
    if (lst == []):
        return 0
    elif getSqn(pkt) < getSqn(lst[0]):
        return 0 + get_pos(pkt,[])
    else:
        return 1 + get_pos(pkt,lst[1:])
            
def removeFromPacketQ(q):
    if not isEmptPacketQ(q):
        contentsQ(q).pop(0)
    else:
        raise IndexError ("queue is empty")
 

def isPacketQ(q):
    return q[0]=="PQ" and type(q)==type(()) and len(q)==2
       
        


def isEmptPacketQ(q):
    if isPacketQ(q):
        return contentsQ(q)==[]
    else:
        raise TypeError("arg must be a queue")
   
        


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

    pkt = makePacket(srcIP, dstIP, length, prt, sp, dp, sqn, pld)
    pk1 = makePacket("111.202.230.44","62.82.29.190",31,"HTTP",80,20,1562431,38)
    pk2 = makePacket("222.57.155.164","50.168.160.19",22,"UDP",90,5431,1662431,82)
    pk3 = makePacket("333.230.18.207","213.217.236.184",56,"IRC",501,5643,1762431,318)
    pk4 = makePacket("444.221.232.94","50.168.160.19",1003,"TCP",4657,4875,1962431,428)
    pk5 = makePacket("555.221.232.94","50.168.160.19",236,"TCP",7753,5724,2062431,48)
    
    pkt_list = [pkt,pk1,pk2,pk3,pk4]
    
    q = makePacketQueue()
    
    ProtocolList = ["HTTP","SMTP","UDP","TCP","DHCP"]
    IpBlackList = ["213.217.236.184","444.221.232.94","149.88.83.47","223.70.250.146","169.51.6.136","229.223.169.245"]
    
    ScoreList = makeScore(pkt_list)
    
    addToPacketQ(pkt,q)
    addToPacketQ(pk1,q)
    addToPacketQ(pk2,q)
    addToPacketQ(pk3,q)
    addToPacketQ(pk4,q)
    addToPacketQ(pk5,q)
    removeFromPacketQ(q)

    fptr.write('Queue Contents => ' + str(contentsQ(q)) + '\n')
    fptr.write('Is Queue Object => ' + str(isPacketQ(q)) + '\n')
    fptr.write('Is Queue Object (2) => ' + str(isPacketQ(("PQ",[],1))) + '\n')
    fptr.write('Is Empty Queue => ' + str(isEmptPacketQ(q)) + '\n')
    fptr.write('Is Empty Queue (2) => ' + str(isPacketQ(("PQ",[]))) + '\n')
    
    

    fptr.close()
