# pcap2yuv
Tool to generate YUV file from pcap file containing RTP packets carrying video encoded in H.264-SVC.<br>
Requires [libopensvc](https://sourceforge.net/projects/opensvcdecoder/).<br>
```
Usage:  ./pcap2yuv.py  <pcap file> <src IP filter> <SSRC filter> [out yuv file] [out pacsi file] [out NAL file]
     <pcap file>      : pcap file name
     <src IP filter>  : source IP address of packets to be decoded. Ex. 10.0.0.1
     <SSRC filter>    : RTP SSRC value of packets to be decoded in decimal format.
                        Use comma to separate multiple SSRCs. Ex. 889614168,889614169
     [out yuv file]   : Output yuv file name. Default is out.yuv
     [out pacsi file] : Output pacsi file name. Default is pacsi.txt
     [out NAL file]   : Output NAL file name. Default is nal.txt
```
