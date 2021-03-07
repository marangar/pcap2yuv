#! /usr/bin/env python

import sys
import os.path
from os import fstat
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as _s
import svcdecoder as svc
from struct import unpack
from pacsi import parse_pacsi

# output files
defYUVFile     = "out.yuv"
defPACSIFIle   = "pacsi.txt"
defNALFile     = "nal.txt"
# constants
warnOutFileSize = 1024*1024*1024
warnUnitMeasure = 'GB'
nalTypeBits     = 0x1f 

def display_help():
    print "Usage: " , sys.argv[0] , " <pcap file> <src IP filter> <SSRC filter> [out yuv file] [out pacsi file] [out NAL file]"
    print "     <pcap file>      : pcap file name"
    print "     <src IP filter>  : source IP address of packets to be decoded. Ex. 10.0.0.1"
    print "     <SSRC filter>    : RTP SSRC value of packets to be decoded in decimal format."
    print "                        Use comma to separate multiple SSRCs. Ex. 889614168,889614169"
    print "     [out yuv file]   : Output yuv file name. Default is", defYUVFile
    print "     [out pacsi file] : Output pacsi file name. Default is", defPACSIFIle
    print "     [out NAL file]   : Output NAL file name. Default is", defNALFile

def display_status(current, total):
    print "\r" + str(current) + "/" + str(total), 
    sys.stdout.flush()    

def display_footer(width, height, outPacsiFile, outNalFile):
    print "Use PYUV for viewing: http://dsplab.diei.unipg.it/pyuv_raw_video_sequence_player_original_one"
    print "Set format YUV 4:2:0 and resolution " + str(width) + "x" + str(height)
    print "Parsed PACSIs are written in" , outPacsiFile 
    print "List of decoded NALs is written in" , outNalFile

def filter_packets(pkts, filterSrcIp, filterSSRC):
    pkts2decode = []
    pktcnt      = 0
    print "Processing packets to be filtered..."
    for p in pkts:
        # display status
        pktcnt += 1
        display_status(pktcnt, len(pkts))         
        # filter
        if p.getlayer(_s.IP) is None:
            continue
        if p.getlayer(_s.UDP) is None:
            continue
        if not filterSrcIp or p[_s.IP].src in filterSrcIp:
            p.getlayer(_s.UDP).decode_payload_as(_s.RTP)
            if p[_s.RTP].version != 2:
                continue
            if not filterSSRC or str(p[_s.RTP].sourcesync) in filterSSRC:
                pkts2decode.append(p)   
    print ""
    return pkts2decode   

def decode_nal_and_write(fd, fdp, fdn, dec, nal, nalSize):
    nalType = nal[0] & nalTypeBits
    if nalType == 30:
        try:
            pacsi = parse_pacsi(nal, nalSize)
            fdp.write('\n')
            fdp.write(str(pacsi))
            fdp.write('\n')
        except Exception as e:
            print "Error parsing PACSI: " , e
    else:
        try:
            rval = dec.decode_nal(nal, nalSize)
            if   rval == svc.SVC_STATUS_OK.value:
                fdn.write("NAL decoded\n")
            elif rval == svc.SVC_IMAGE_READY.value:
                fdn.write("Got image. Width: " + str(dec.frame.Width) + 
                          " , Height: " + str(dec.frame.Height) + "\n")
                dec.write_frame(fd)        
            elif rval == svc.SVC_GHOST_IMAGE.value:
                fdn.write("Got ghost image\n")
        except svc.SVCException as svcE:
            print "Error decoding NAL: " , svcE

def decode_packet(fd, fdp, fdn, dec, nalBuf, p):
    rawStr = p.getlayer(_s.Raw).load
    nal = bytearray(rawStr)
    nalSize = len(nal)
    nalType = nal[0] & nalTypeBits
    fdn.write("NAL type: " + str(nalType) + "\n")
    # Single NAL
    if 1 <= nalType <= 23 or nalType == 30:
        decode_nal_and_write(fd, fdp, fdn, dec, nal, nalSize) 
    # STAP-A NAL
    if nalType == 24:
        P = 1
        while P < nalSize:
            subNalSize = unpack('>H', str(nal[P : P + 2]))[0]
            P += 2
            subNal     = nal[P : P + subNalSize]
            subNalType = subNal[0] & nalTypeBits
            fdn.write("Sub NAL type: " + str(subNalType) + "\n")
            decode_nal_and_write(fd, fdp, fdn, dec, subNal, subNalSize) 
            P += subNalSize 
    # FU-A or FU-B NAL
    if nalType == 28 or nalType == 29:
        P = 0
        S = (nal[P + 1] & 0x80) == 0x80
        E = (nal[P + 1] & 0x40) == 0x40
        if S:
            nalHeader = (nal[P] & 0xe0) | (nal[P + 1] & nalTypeBits)
            nalBuf.append(nalHeader)
            nalBuf.extend(nal[P + 2 : P + nalSize])
        else:
            nalBuf.extend(nal[P + 2 : P + nalSize])
            if E:
                recNalType = nalBuf[0] & nalTypeBits
                fdn.write("Reconstructed NAL type: " + str(recNalType) + "\n")
                decode_nal_and_write(fd, fdp, fdn, dec, nalBuf, len(nalBuf)) 
                nalBuf[:] = bytearray()

def base_dir_exist(fileName): 
    outDirName = os.path.dirname(fileName)
    if outDirName and not os.path.isdir(outDirName):
        print "Directory" , outDirName, "does not exist"
        return False
    return True

def main(pcapFile, filterSrcIp, filterSSRC, outFile, outPacsiFile, outNalFile):
    warnDisplayed = False
    filterSrcIp   = filterSrcIp.split(',') if filterSrcIp else ''
    filterSSRC    = filterSSRC.split(',')  if filterSSRC  else ''
    # check files existence
    if not os.path.isfile(pcapFile):
        print "File " + pcapFile + " does not exist"
        return 1
    if not base_dir_exist(outFile):
        return 1
    if not base_dir_exist(outPacsiFile):
        return 1
    if not base_dir_exist(outNalFile):
        return 1        
    # process and filter pcap
    print "Parsing PCAP file..."
    pkts = _s.rdpcap(pcapFile)
    pkts2decode = filter_packets(pkts, filterSrcIp, filterSSRC)
    if not len(pkts2decode):
        print "No packets found for applied filters (src-IP = " + str(filterSrcIp) + \
                                                   " ; SSRC = " + str(filterSSRC) + ")"
        return 1
    # decode packets
    fd     = open(outFile, 'wb')  
    fdp    = open(outPacsiFile, 'w')
    fdn    = open(outNalFile, 'w')
    dec    = svc.SVCDecoder()
    nalBuf = bytearray()
    pktcnt = 0
    print "Decoding" , len(pkts2decode) , "packets ... "
    for p in pkts2decode:
        # decode
        decode_packet(fd, fdp, fdn, dec, nalBuf, p) 
        # display status
        pktcnt += 1
        display_status(pktcnt, len(pkts2decode))
        # check yuv file size
        if not warnDisplayed and fstat(fd.fileno()).st_size > warnOutFileSize:
            print ""
            print ""
            print "WARNING: YUV file size exceeds 1", warnUnitMeasure
            print "if you stop the program, initial part of YUV file is still readable"
            print "YUV file is written in", outFile
            display_footer(dec.frame.Width, dec.frame.Height, outPacsiFile, outNalFile)
            print ""
            warnDisplayed = True
    print ""                         
    dec.close()
    fdn.close()
    fdp.close()
    fd.close()
    # display final message
    print ""
    print "YUV file written in", outFile
    display_footer(dec.frame.Width, dec.frame.Height, outPacsiFile, outNalFile)
    return 0  

if __name__ == "__main__":
    if not 4 <= len(sys.argv) <= 7:
        display_help()
        exit(1)	
    pcapFileIn    = sys.argv[1]
    filterSrcIpIn = sys.argv[2]
    filterSSRCIn  = sys.argv[3]
    if len(sys.argv) == 5: 
        outFileIn      = sys.argv[4]
        outPacsiFileIn = defYUVFile
        outNalFileIn   = defNALFile
    elif len(sys.argv) == 6:
        outFileIn      = sys.argv[4]
        outPacsiFileIn = sys.argv[5]
        outNalFileIn   = defNALFile
    elif len(sys.argv) == 7:
        outFileIn      = sys.argv[4]
        outPacsiFileIn = sys.argv[5]
        outNalFileIn   = sys.argv[6]    
    else:
        outFileIn      = defYUVFile
        outPacsiFileIn = defPACSIFIle 
        outNalFileIn   = defNALFile   
    # real main
    exit(main(pcapFileIn, filterSrcIpIn, filterSSRCIn, outFileIn, outPacsiFileIn, outNalFileIn))
