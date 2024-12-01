#!/bin/python3

import math
import os
import random
import re
import sys

#
# Please Paste all Fuctions from Part 1,2,3,4,5,6 & 7
# Complete the function below.
#

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

def flowAverage(packet_List):#This metric will accept a list of packets and gets the average payload size
#of all the packets. It will return a list of packets that are above the average of the list
    
    lstPack=[]
    size=0
    for pkt in packet_List:
        size+=getPayloadSize(pkt)
    average=size/len(packet_List)
    
    for pkt in packet_List:
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
    BlackList=["213.217.236.184","149.88.83.47","223.70.250.146","169.51.6.136","229.223.169.245"]
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
    if pkt in flowAverage(lst):
        score+=3.56 
    return score
    print("calcscore output:",score)
 
        
def makeScore(pkt_list):
    scorelist=[]
    for pkt in pkt_list:
        scorelist+= [(pkt,calScore(pkt))]
    return ['score',[scorelist]]
 
def Slist_contents(ScoreList):
    print (ScoreList)
    return ScoreList[1][0]

def addPacket(ScoreList, pkt):
    score=calScore(pkt)
    return Slist_contents(ScoreList).append((pkt,score))
  

def getSuspPkts(ScoreList):
    newlist=[pkt for pkt,score in Slist_contents(ScoreList)] if score >5.00]
    return newlist


def getRegulPkts(ScoreList):#Takes a Score as an input and returns a list of all regular packets.
    newlist=[pkt for pkt,score in Slist_contents(ScoreList) if score<=5.00]
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
    
#--------------------------------Part 6------------------------------------------------------------------------------------------------------

def makePacketStack():
    return ("PS",[])

def contentsStack(stk):
    return stk[1]

def topProjectStack(stk):
    if not isEmptyPKStack(stk) and isPKstack(stk):
        return contentsStack(stk)[-1]
    else:
        raise TypeError ("Must be a stack and must not be empty")


def pushProjectStack(pkt,stk):
    if isPKstack(stk):
        contentsStack(stk).append(pkt)
    else:
        raise TypeError ("Must be a stack")


def popPickupStack(stk):
    contentsStack(stk).pop()

def isPKstack(stk):
    return type(stk)==type(()) and stk[0]=="PS" and type(contentsStack(stk))==type([])

def isEmptyPKStack(stk):
    if isPKstack(stk):
        return contentsStack(stk)==[]
    else:
        raise TypeError ("Must be a stack")

#---------------------------------------------------------Part 7-----------------------------------------------
def sortPackets(scoreList,stack,queue):
    keep=(getRegulPkts(scoreList))
    discard=getSuspPkts(scoreList)
    for k in keep:
        addToPacketQ(k,queue)
    for d in discard:
        pushProjectStack(d,stack)
        



#-------------------------Part 8------------------------------------------------------------------
def analysePackets(packet_List):
    
        pQueue = makePacketQueue()
        pStack = makePacketStack()

        # Convert raw packets into packet objects
        lst = [makePacket(*pkts) for pkts in packet_List]
       

        # Create a Score ADT using the formatted packet objects
        scoreList = makeScore(lst)
       

        # Sort packets into queue and stack
        sortPackets(scoreList, pStack, pQueue)
        print("queue",pQueue)
        print("stack:",pStack)
        print("ScoreList:",scoreList)

        # Sort the queue by sequence number in descending order
        contentsQ(pQueue).sort(key=lambda pkt: getSqn(pkt), reverse=False)

        return pQueue

   




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
    
    ProtocolList = ["HTTPS","SMTP","UDP","TCP","DHCP","IRC"]
    IpBlackList = ["213.217.236.184","149.88.83.47","223.70.250.146","169.51.6.136","229.223.169.245"]
    
    packet_List = [(srcIP, dstIP, length, prt, sp, dp, sqn, pld),\
              ("111.202.230.44","62.82.29.190",31,"HTTP",80,20,1562436,338),\
              ("222.57.155.164","50.168.160.19",22,"UDP",790,5431,1662435,812),\
              ("333.230.18.207","213.217.236.184",56,"IMCP",501,5643,1762434,3138),\
              ("444.221.232.94","50.168.160.19",1003,"TCP",4657,4875,1962433,428),\
              ("555.221.232.94","50.168.160.19",236,"HTTP",7753,5724,2062432,48)]
    
    lst = [makePacket(*pkts) for pkts in packet_List]
    
    analysePackets(packet_List)
    
    
    fptr.write('Forward Packets => ' + str(analysePackets(packet_List)) + '\n')
    
    fptr.close()
