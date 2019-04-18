// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//

from impacket import structure

O_ETH = 0
O_IP  = 1
O_ARP = 1
O_UDP = 2
O_TCP = 2
O_ICMP = 2
O_UDP_DATA = 3
O_ICMP_DATA = 3

MAGIC = ""\xD4\xC3\xB2\xA1"

 type PCapFileHeader struct { // structure.Structure: (
        ('magic', MAGIC),
         versionMajor uint16 // =2
         versionMinor uint16 // =4
        ('GMT2localCorrection', '<l=0'),
         timeAccuracy uint32 // =0
         maxLength uint32 // =0xffff
         linkType uint32 // =1
        ('packets','*:=[]'),
    }

 type PCapFilePacket struct { // structure.Structure: (
         tsec uint32 // =0
         tmsec uint32 // =0
         savedLength uint32 // -data
         realLength uint32 // -data
        ('data',':'),
    }

     func (self TYPE) __init__(*args, **kargs interface{}){
        structure.Structure.__init__(self, *args, **kargs)
        self.data = b''

 type PcapFile: struct {
     func (self TYPE) __init__(fileName = nil, mode = "rb" interface{}){
        if fileName is not nil {
           self.file = open(fileName, mode)
        self.hdr = nil
        self.wroteHeader = false

     func (self TYPE) reset(){
        self.hdr = nil
        self.file.seek(0)

     func (self TYPE) close(){
        self.file.close()

     func (self TYPE) fileno(){
        return self.file.fileno()

     func (self TYPE) setFile(file interface{}){
        self.file = file

     func (self TYPE) setSnapLen(snapLen interface{}){
        self.createHeaderOnce()
        self.hdr["maxLength"] = snapLen

     func (self TYPE) getSnapLen(){
        self.readHeaderOnce()
        return self.hdr["maxLength"]

     func (self TYPE) setLinkType(linkType interface{}){
        self.createHeaderOnce()
        self.hdr["linkType"] = linkType

     func (self TYPE) getLinkType(){
        self.readHeaderOnce()
        return self.hdr["linkType"]

     func (self TYPE) readHeaderOnce(){
        if self.hdr == nil {
           self.hdr = PCapFileHeader.fromFile(self.file)

     func (self TYPE) createHeaderOnce(){
        if self.hdr == nil {
           self.hdr = PCapFileHeader()
    
     func (self TYPE) writeHeaderOnce(){
        if not self.wroteHeader {
           self.wroteHeader = true
           self.file.seek(0)
           self.createHeaderOnce()
           self.file.write(self.hdr.getData())

     func (self TYPE) read(){
       self.readHeaderOnce()
       try:
          pkt = PCapFilePacket.fromFile(self.file)
          pkt["data"] = self.file.read(pkt["savedLength"])
          return pkt
       except:
          return nil

     func (self TYPE) write(pkt interface{}){
        self.writeHeaderOnce()
        self.file.write(str(pkt))

     func (self TYPE) packets(){
        self.reset()
        while 1:
           answer = self.read()
           if answer == nil {
               break
           yield answer
