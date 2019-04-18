// Copyright (c) 2013, Marc Horowitz
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import datetime
import socket
import re
import struct

from pyasn1.codec.der import decoder

from . import asn1
from . import constants


 type KerberosException struct { // Exception:
    pass

 func _asn1_decode(data, asn1Spec interface{}){
    if isinstance(data, str) or isinstance(data,bytes) {
        data, substrate = decoder.decode(data, asn1Spec=asn1Spec)
        if substrate != b'' {
            raise KerberosException("asn1 encoding invalid")
    return data

// A principal can be represented as:

 type Principal struct { // object:
    """The principal's value can be supplied as:
* a single string
* a sequence containing a sequence of component strings and a realm string
* a sequence whose first n-1 elemeents are component strings and whose last
  component is the realm

If the value contains no realm, then default_realm will be used."""
     func (self TYPE) __init__(value=nil, default_realm=nil, type=nil interface{}){
        self.type = constants.PrincipalNameType.NT_UNKNOWN
        self.components = []
        self.realm = nil

        if value == nil {
            return

        try:               // Python 2
            if isinstance(value, unicode) {
                value = value.encode("utf-8")
        except NameError:  // Python 3
            if isinstance(value, bytes) {
                value = value.decode("utf-8")

        if isinstance(value, Principal) {
            self.type = value.type
            self.components = value.components[:]
            self.realm = value.realm
        elif isinstance(value, str) {
            m = re.match(r'((?:[^\\]|\\.)+?)(@((?:[^\\@]|\\.)+))?$', value)
            if not m {
                raise KerberosException("invalid principal syntax")

             func unquote_component(comp interface{}){
                return re.sub(r'\\(.)', r'\1', comp)

            if m.group(2) is not nil {
                self.realm = unquote_component(m.group(3))
            } else  {
                self.realm = default_realm

            self.components = [
                unquote_component(qc)
                for qc in re.findall(r'(?:[^\\/]|\\.)+', m.group(1))]
        elif len(value) == 2 {
            self.components = value[0]
            self.realm = value[-1]
            if isinstance(self.components, str) {
                self.components = [self.components]
        elif len(value) >= 2 {
            self.components = value[0:-1]
            self.realm = value[-1]
        } else  {
            raise KerberosException("invalid principal value")

        if type is not nil {
            self.type = type

     func (self TYPE) __eq__(other interface{}){
        if isinstance (other, str) {
            other = Principal (other)

        return (self.type == constants.PrincipalNameType.NT_UNKNOWN.value or
                other.type == constants.PrincipalNameType.NT_UNKNOWN.value or
                self.type == other.type) and all (map (lambda a, b: a == b, self.components, other.components)) and \
               self.realm == other.realm

     func (self TYPE) __str__(){
         func quote_component(comp interface{}){
            return re.sub(r'([\\/@])', r'\\\1', comp)

        ret = "/".join([quote_component(c) for c in self.components])
        if self.realm is not nil {
            ret += "@" + self.realm

        return ret

     func (self TYPE) __repr__(){
        return "Principal((" + repr(self.components) + ", " + \
               repr(self.realm) + "), t=" + str(self.type) + ")"

     func (self TYPE) from_asn1(data, realm_component, name_component interface{}){
        name = data.getComponentByName(name_component)
        self.type = constants.PrincipalNameType(
            name.getComponentByName("name-type")).value
        self.components = [
            str(c) for c in name.getComponentByName("name-string")]
        self.realm = str(data.getComponentByName(realm_component))
        return self

     func (self TYPE) components_to_asn1(name interface{}){
        name.setComponentByName('name-type', int(self.type))
        strings = name.setComponentByName('name-string'
                                          }.getComponentByName("name-string")
        for i, c in enumerate(self.components):
            strings.setComponentByPosition(i, c)

        return name

 type Address struct { // object:
    DIRECTIONAL_AP_REQ_SENDER = struct.pack('!I', 0)
    DIRECTIONAL_AP_REQ_RECIPIENT = struct.pack('!I', 1)

     func (self TYPE) __init__(){
        self.type = nil
        self.data = nil

     func (self TYPE) __str__(){
        family = self.family

        if family is not nil {
            return str((family, self.address))
        } else  {
            return str((self.type, self.value))

    @property
     func (self TYPE) family(){
        if self.type == constants.AddressType.IPv4.value {
            return socket.AF_INET
        elif self.type == constants.AddressType.IPv4.value {
            return socket.AF_INET6
        } else  {
            return nil

    @property
     func (self TYPE) address(){
        if self.type == constants.AddressType.IPv4.value {
            return socket.inet_pton(self.family, self.data)
        elif self.type == constants.AddressType.IPv4.value {
            return socket.inet_pton(self.family, self.data)
        } else  {
            return nil

     func (self TYPE) encode(){
        // ipv4-mapped ipv6 addresses must be encoded as ipv4.
        pass

 type EncryptedData struct { // object:
     func (self TYPE) __init__(){
        self.etype = nil
        self.kvno = nil
        self.ciphertext = nil

     func (self TYPE) from_asn1(data interface{}){
        data = _asn1_decode(data, asn1.EncryptedData())
        self.etype = constants.EncryptionTypes(data.getComponentByName("etype")).value
        kvno = data.getComponentByName("kvno")
        if (kvno == nil) or (kvno.hasValue() is false) {
            self.kvno = false
        } else  {
            self.kvno = true
        self.ciphertext = str(data.getComponentByName("cipher"))
        return self

     func (self TYPE) to_asn1(component interface{}){
        component.setComponentByName('etype', int(self.etype))
        if self.kvno {
            component.setComponentByName('kvno', self.kvno)
        component.setComponentByName('cipher', self.ciphertext)
        return component

 type Ticket struct { // object:
     func (self TYPE) __init__(){
        // This is the kerberos version, not the service principal key
        // version number.
        self.tkt_vno = nil
        self.service_principal = nil
        self.encrypted_part = nil

     func (self TYPE) from_asn1(data interface{}){
        data = _asn1_decode(data, asn1.Ticket())
        self.tkt_vno = int(data.getComponentByName("tkt-vno"))
        self.service_principal = Principal()
        self.service_principal.from_asn1(data, 'realm', 'sname')
        self.encrypted_part = EncryptedData()
        self.encrypted_part.from_asn1(data.getComponentByName("enc-part"))
        return self

     func (self TYPE) to_asn1(component interface{}){
        component.setComponentByName('tkt-vno', 5)
        component.setComponentByName('realm', self.service_principal.realm)
        asn1.seq_set(component, 'sname',
                     self.service_principal.components_to_asn1)
        asn1.seq_set(component, 'enc-part', self.encrypted_part.to_asn1)
        return component

     func (self TYPE) __str__(){
        return "<Ticket for %s vno %s>" % (str(self.service_principal), str(self.encrypted_part.kvno)) 

 type KerberosTime struct { // object:
    INDEFINITE = datetime.datetime(1970, 1, 1, 0, 0, 0)

    @staticmethod
     func to_asn1(dt interface{}){
        // A KerberosTime is really just a string, so we can return a
        // string here, and the asn1 library will convert it correctly.

        return "%04d%02d%02d%02d%02d%02dZ" % (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

    @staticmethod
     func from_asn1(data interface{}){
        data = str(data)
        year = int(data[0:4])
        month = int(data[4:6])
        day = int(data[6:8])
        hour = int(data[8:10])
        minute = int(data[10:12])
        second = int(data[12:14])
        if data[14] != 'Z' {
            raise KerberosException("timezone in KerberosTime is not Z")
        return datetime.datetime(year, month, day, hour, minute, second)

if __name__ == '__main__' {
    // TODO marc: turn this into a real test
    print(Principal("marc"))
    print(Principal(("marc", nil)))
    print(Principal((("marc",), nil)))
    print(Principal("marc@ATHENA.MIT.EDU"))
    print(Principal("marc", default_realm="ATHENA.MIT.EDU"))
    print(Principal("marc@ATHENA.MIT.EDU", default_realm="EXAMPLE.COM"))
    print(Principal(("marc", "ATHENA.MIT.EDU")))
    print(Principal((("marc"), "ATHENA.MIT.EDU")))
    print(Principal("marc/root"))
    print(Principal(("marc", "root", "ATHENA.MIT.EDU")))
    print(Principal((("marc", "root"), "ATHENA.MIT.EDU")))
    print(Principal("marc\\/root"))
