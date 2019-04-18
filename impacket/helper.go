// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Description:
//  Helper used to build ProtocolPackets
//
// Author:
// Aureliano Calvo


import struct
import functools
from six import add_metaclass

import impacket.ImpactPacket as ip


 func rebind(f interface{}){
    functools.wraps(f)
     func rebinder(*args, **kwargs interface{}){
        return f(*args, **kwargs)
        
    return rebinder

 type Field struct { // object:
     func (self TYPE) __init__(index interface{}){
        self.index = index
    
     func (self TYPE) __call__(k, d interface{}){
        getter = rebind(self.getter)
        getter_name = "get_" + k
        getter.__name__ = getter_name
        getter.__doc__ = "Get the %s field" % k
        d[getter_name] = getter
        
        setter = rebind(self.setter)
        setter_name = "set_" + k
        setter.__name__ = setter_name
        setter.__doc__ = "Set the %s field" % k
        d["set_" + k] = setter
        
        d[k] = property(getter, setter, doc="%s property" % k)
        
 type Bit struct { // Field:
     func (self TYPE) __init__(index, bit_number interface{}){
        Field.__init__(self, index)
        self.mask = 2 ** bit_number
        self.off_mask = (~self.mask) & 0xff
        
     func (self TYPE) getter(o interface{}){
        return (o.header.get_byte(self.index) & self.mask) != 0
    
     func (self TYPE) setter(o, value=true interface{}){
        b = o.header.get_byte(self.index)
        if value {
            b |= self.mask
        } else  {
            b &= self.off_mask
        
        o.header.set_byte(self.index, b) 

 type Byte struct { // Field:
    
     func (self TYPE) __init__(index interface{}){
        Field.__init__(self, index)
        
     func (self TYPE) getter(o interface{}){
        return o.header.get_byte(self.index)
    
     func (self TYPE) setter(o, value interface{}){
        o.header.set_byte(self.index, value)
        
 type Word struct { // Field:
     func (self TYPE) __init__(index, order="!" interface{}){
        Field.__init__(self, index)
        self.order = order
        
     func (self TYPE) getter(o interface{}){
        return o.header.get_word(self.index, self.order)
    
     func (self TYPE) setter(o, value interface{}){
        o.header.set_word(self.index, value, self.order)

 type Long struct { // Field:        
     func (self TYPE) __init__(index, order="!" interface{}){
        Field.__init__(self, index)        
        self.order = order
        
     func (self TYPE) getter(o interface{}){
        return o.header.get_long(self.index, self.order)
    
     func (self TYPE) setter(o, value interface{}){
        o.header.set_long(self.index, value, self.order)
        
 type ThreeBytesBigEndian struct { // Field:
     func (self TYPE) __init__(index interface{}){
        Field.__init__(self, index)
                
     func (self TYPE) getter(o interface{}){
        b=o.header.get_bytes()[self.index:self.index+3].tostring()
        //unpack requires a string argument of length 4 and b is 3 bytes long
        (value,)=struct.unpack('!L', b'\x00'+b)
        return value

     func (self TYPE) setter(o, value interface{}){
        // clear the bits
        mask = ((~0xFFFFFF00) & 0xFF)
        masked = o.header.get_long(self.index, ">") & mask
        // set the bits 
        nb = masked | ((value & 0x00FFFFFF) << 8)
        o.header.set_long(self.index, nb, ">")


 type ProtocolPacketMetaklass struct { // type:
     func __new__(cls, name, bases, d interface{}){
        d["_fields"] = []
        items = list(d.items())
        if not object in bases {
            bases += (object,)
        for k,v in items:
            if isinstance(v, Field) {
                d["_fields"].append(k) 
                v(k, d)
                
        d["_fields"].sort()
        
         func (self TYPE) _fields_repr(){
            return " ".join( "%s:%s" % (f, repr(getattr(self, f))) for f in self._fields )
         func (self TYPE) __repr__(){
            
            return "<%(name)s %(fields)s \nchild:%(r_child)s>" % {
                "name": name,
                "fields": self._fields_repr(),
                "r_child": repr(self.child()), 
            }
        
        d["_fields_repr"] = _fields_repr
        d["__repr__"] = __repr__
        
        return type.__new__(cls, name, bases, d)

@add_metaclass(ProtocolPacketMetaklass)
 type ProtocolPacket struct { // ip.ProtocolPacket:
     func (self TYPE) __init__(buff = nil interface{}){
        ip.ProtocolPacket.__init__(self, self.header_size, self.tail_size)
        if buff {
            self.load_packet(buff)
