// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-WMI]/[MS-WMIO] : Windows Management Instrumentation Remote Protocol. Partial implementation
//
//   Best way to learn how to use these calls is to grab the protocol standard
//   so you understand what the call does, and then read the test case located
//   at https://github.com/SecureAuthCorp/impacket/tree/master/tests/SMB_RPC
//
//   Since DCOM is like an OO RPC, instead of helper functions you will see the 
//   classes described in the standards developed. 
//   There are test cases for them too. 
//
from __future__ import division
from __future__ import print_function
from struct import unpack, calcsize, pack
from functools import partial
import collections
import logging

from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRUniConformantArray, NDRPOINTER, NDRUniConformantVaryingArray, NDRUNION, \
    NDRENUM
from impacket.dcerpc.v5.dcomrt import DCOMCALL, DCOMANSWER, IRemUnknown, PMInterfacePointer, INTERFACE, \
    PMInterfacePointer_ARRAY, BYTE_ARRAY, PPMInterfacePointer, OBJREF_CUSTOM
from impacket.dcerpc.v5.dcom.oaut import BSTR
from impacket.dcerpc.v5.dtypes import ULONG, DWORD, NULL, LPWSTR, LONG, HRESULT, PGUID, LPCSTR, GUID
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import hresult_errors, LOG
from impacket.uuid import string_to_bin, uuidtup_to_bin
from impacket.structure import Structure, hexdump


 func format_structure(d, level=0 interface{}){
    x = ""
    if isinstance(d, collections.Mapping) {
        lenk = max([len(str(x)) for x in list(d.keys())])
        for k, v in list(d.items()):
            key_text = "\n" + " "*level + " "*(lenk - len(str(k))) + str(k)
            x += key_text + ": " + format_structure(v, level=level+lenk)
    elif isinstance(d, collections.Iterable) and not isinstance(d, str) {
        for e in d:
            x += "\n" + " "*level + "- " + format_structure(e, level=level+4)
    } else  {
        x = str(d)
    return x
try:
    from collections import OrderedDict
except:
    try:
        from ordereddict.ordereddict import OrderedDict
    except:
        from ordereddict import OrderedDict

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        if self.error_code in hresult_errors.ERROR_MESSAGES {
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1] 
            return 'WMI SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            // Let's see if we have it as WBEMSTATUS
            try:
                return 'WMI Session Error: code: 0x%x - %s' % (self.error_code, WBEMSTATUS.enumItems(self.error_code).name)
            except:
                return 'WMI SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// WMIO Structures and Constants
//###############################################################################
WBEM_FLAVOR_FLAG_PROPAGATE_O_INSTANCE      = 0x01
WBEM_FLAVOR_FLAG_PROPAGATE_O_DERIVED_CLASS = 0x02
WBEM_FLAVOR_NOT_OVERRIDABLE                = 0x10
WBEM_FLAVOR_ORIGIN_PROPAGATED              = 0x20
WBEM_FLAVOR_ORIGIN_SYSTEM                  = 0x40
WBEM_FLAVOR_AMENDED                        = 0x80

// 2.2.6 ObjectFlags
OBJECT_FLAGS = "B=0"

//2.2.77 Signature
SIGNATURE = "<L=0x12345678"

// 2.2.4 ObjectEncodingLength
OBJECT_ENCODING_LENGTH = "<L=0"

// 2.2.73 EncodingLength
ENCODING_LENGTH = "<L=0"

// 2.2.78 Encoded-String
ENCODED_STRING_FLAG = "B=0"

// 2.2.76 ReservedOctet
RESERVED_OCTET = "B=0"

// 2.2.28 NdTableValueTableLength
NDTABLE_VALUE_TABLE_LENGTH = "<L=0"

// 2.2.80 DictionaryReference
DICTIONARY_REFERENCE = {
    0 : '"',
    1 : 'key',
    2 : 'NADA',
    3 : 'read',
    4 : 'write',
    5 : 'volatile',
    6 : 'provider',
    7 : 'dynamic',
    8 : 'cimwin32',
    9 : 'DWORD',
   10 : 'CIMTYPE',
}

 type ENCODED_STRING struct { // Structure:
    commonHdr = (
        ('Encoded_String_Flag', ENCODED_STRING_FLAG),
    }

    tascii = (
        ('Character', 'z'),
    }

    tunicode = (
        ('Character', 'u'),
    }

     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self, data, alignment)
        if data is not nil {
            // Let's first check the commonHdr
            self.fromString(data)
            self. ()
            self.isUnicode = false
            if len(data) > 1 {
                if self.Encoded_String_Flag == 0 {
                    self.structure += self.tascii
                    // Let's search for the end of the string
                    index = data[1:].find(b'\x00')
                    data  = data[:index+1+1]
                } else  {
                    self. self.tunicode
                    self.isUnicode = true

                self.fromString(data)
        } else  {
            self. self.tascii
            self.data = nil

     func (self TYPE) __getitem__(key interface{}){
        if key == 'Character' and self.isUnicode {
            return self.fields["Character"].decode("utf-16le")
        return Structure.__getitem__(self, key)


// 2.2.8 DecServerName
DEC_SERVER_NAME = ENCODED_STRING

// 2.2.9 DecNamespaceName
DEC_NAMESPACE_NAME = ENCODED_STRING

// 2.2.7 Decoration
 type DECORATION struct { // Structure: (
        ('DecServerName', ':', DEC_SERVER_NAME),
        ('DecNamespaceName', ':', DEC_NAMESPACE_NAME),
    }

// 2.2.69 HeapRef
HEAPREF = "<L=0"

// 2.2.68 HeapStringRef
HEAP_STRING_REF = HEAPREF

// 2.2.19 ClassNameRef
CLASS_NAME_REF = HEAP_STRING_REF

// 2.2.16 ClassHeader
 type CLASS_HEADER struct { // Structure: (
        ('EncodingLength', ENCODING_LENGTH),
        ('ReservedOctet', RESERVED_OCTET),
        ('ClassNameRef', CLASS_NAME_REF),
        ('NdTableValueTableLength', NDTABLE_VALUE_TABLE_LENGTH),
    }

// 2.2.17 DerivationList
 type DERIVATION_LIST struct { // Structure: (
        ('EncodingLength', ENCODING_LENGTH),
        ('_ClassNameEncoding','_-ClassNameEncoding', 'self.EncodingLength-4'),
        ('ClassNameEncoding', ':'),
    }

// 2.2.82 CimType
CIM_TYPE = "<L=0"
CIM_ARRAY_FLAG = 0x2000

 type EnumType struct { // type:
     func (self TYPE) __getattr__(attr interface{}){
        return self.enumItems[attr].value

 type CIM_TYPE_ENUM struct { // Enum:
//    __metaclass__ = EnumType
    CIM_TYPE_SINT8      = 16
    CIM_TYPE_UINT8      = 17
    CIM_TYPE_SINT16     = 2
    CIM_TYPE_UINT16     = 18
    CIM_TYPE_SINT32     = 3
    CIM_TYPE_UINT32     = 19
    CIM_TYPE_SINT64     = 20
    CIM_TYPE_UINT64     = 21
    CIM_TYPE_REAL32     = 4
    CIM_TYPE_REAL64     = 5
    CIM_TYPE_BOOLEAN    = 11
    CIM_TYPE_STRING     = 8
    CIM_TYPE_DATETIME   = 101
    CIM_TYPE_REFERENCE  = 102
    CIM_TYPE_CHAR16     = 103
    CIM_TYPE_OBJECT     = 13
    CIM_ARRAY_SINT8     = 8208
    CIM_ARRAY_UINT8     = 8209
    CIM_ARRAY_SINT16    = 8194
    CIM_ARRAY_UINT16    = 8210
    CIM_ARRAY_SINT32    = 8195
    CIM_ARRAY_UINT32    = 8201
    CIM_ARRAY_SINT64    = 8202
    CIM_ARRAY_UINT64    = 8203
    CIM_ARRAY_REAL32    = 8196
    CIM_ARRAY_REAL64    = 8197
    CIM_ARRAY_BOOLEAN   = 8203
    CIM_ARRAY_STRING    = 8200
    CIM_ARRAY_DATETIME  = 8293
    CIM_ARRAY_REFERENCE = 8294
    CIM_ARRAY_CHAR16    = 8295
    CIM_ARRAY_OBJECT    = 8205

CIM_TYPES_REF = {
    CIM_TYPE_ENUM.CIM_TYPE_SINT8.value    : 'b=0',
    CIM_TYPE_ENUM.CIM_TYPE_UINT8.value    : 'B=0',
    CIM_TYPE_ENUM.CIM_TYPE_SINT16.value   : '<h=0',
    CIM_TYPE_ENUM.CIM_TYPE_UINT16.value   : '<H=0',
    CIM_TYPE_ENUM.CIM_TYPE_SINT32.value   : '<l=0',
    CIM_TYPE_ENUM.CIM_TYPE_UINT32.value   : '<L=0',
    CIM_TYPE_ENUM.CIM_TYPE_SINT64.value   : '<q=0',
    CIM_TYPE_ENUM.CIM_TYPE_UINT64.value   : '<Q=0',
    CIM_TYPE_ENUM.CIM_TYPE_REAL32.value   : '<f=0',
    CIM_TYPE_ENUM.CIM_TYPE_REAL64.value   : '<d=0',
    CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value  : '<H=0',
    CIM_TYPE_ENUM.CIM_TYPE_STRING.value   : HEAPREF,
    CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value : HEAPREF,
    CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value: HEAPREF,
    CIM_TYPE_ENUM.CIM_TYPE_CHAR16.value   : '<H=0',
    CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value   : HEAPREF,
}

CIM_TYPE_TO_NAME = {
    CIM_TYPE_ENUM.CIM_TYPE_SINT8.value    : 'sint8',
    CIM_TYPE_ENUM.CIM_TYPE_UINT8.value    : 'uint8',
    CIM_TYPE_ENUM.CIM_TYPE_SINT16.value   : 'sint16',
    CIM_TYPE_ENUM.CIM_TYPE_UINT16.value   : 'uint16',
    CIM_TYPE_ENUM.CIM_TYPE_SINT32.value   : 'sint32',
    CIM_TYPE_ENUM.CIM_TYPE_UINT32.value   : 'uint32',
    CIM_TYPE_ENUM.CIM_TYPE_SINT64.value   : 'sint64',
    CIM_TYPE_ENUM.CIM_TYPE_UINT64.value   : 'uint64',
    CIM_TYPE_ENUM.CIM_TYPE_REAL32.value   : 'real32',
    CIM_TYPE_ENUM.CIM_TYPE_REAL64.value   : 'real64',
    CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value  : 'bool',
    CIM_TYPE_ENUM.CIM_TYPE_STRING.value   : 'string',
    CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value : 'datetime',
    CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value: 'reference',
    CIM_TYPE_ENUM.CIM_TYPE_CHAR16.value   : 'char16',
    CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value   : 'object',
}

// 2.2.61 QualifierName
QUALIFIER_NAME = HEAP_STRING_REF

// 2.2.62 QualifierFlavor
QUALIFIER_FLAVOR = "B=0"

// 2.2.63 QualifierType
QUALIFIER_TYPE = CIM_TYPE

// 2.2.71 EncodedValue
 type ENCODED_VALUE struct { // Structure: (
        ('QualifierName', QUALIFIER_NAME),
    }

    @classmethod
     func getValue(cls, cimType, entry, heap interface{}){
        // Let's get the default Values
        pType = cimType & (~(CIM_ARRAY_FLAG|Inherited))

        if entry != 0xffffffff {
            heapData = heap[entry:]
            if cimType & CIM_ARRAY_FLAG {
                // We have an array, let's set the right unpackStr and dataSize for the array contents
                dataSize = calcsize(HEAPREF[:-2])
                numItems = unpack(HEAPREF[:-2], heapData[:dataSize])[0]
                heapData = heapData[dataSize:]
                array = list()
                unpackStrArray =  CIM_TYPES_REF[pType][:-2]
                dataSizeArray = calcsize(unpackStrArray)
                if cimType == CIM_TYPE_ENUM.CIM_ARRAY_STRING.value {
                    // We have an array of strings
                    // First items are DWORDs with the string pointers
                    // inside the heap. We don't need those ones
                    heapData = heapData[4*numItems:]
                    // Let's now grab the strings
                    for _ in range(numItems):
                        item = ENCODED_STRING(heapData)
                        array.append(item["Character"])
                        heapData = heapData[len(item.getData()):]
                elif cimType == CIM_TYPE_ENUM.CIM_ARRAY_OBJECT.value {
                    // Discard the pointers
                    heapData = heapData[dataSize*numItems:]
                    for item in range(numItems):
                        msb = METHOD_SIGNATURE_BLOCK(heapData)
                        unit = ENCODING_UNIT()
                        unit["ObjectEncodingLength"] = msb["EncodingLength"]
                        unit["ObjectBlock"] = msb["ObjectBlock"]
                        array.append(unit)
                        heapData = heapData[msb["EncodingLength"]+4:]
                } else  {
                    for item in range(numItems):
                        // ToDo: Learn to unpack the rest of the array of things
                        array.append(unpack(unpackStrArray, heapData[:dataSizeArray])[0])
                        heapData = heapData[dataSizeArray:]
                value = array
            elif pType == CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value {
                if entry == 0xffff {
                    value = "true"
                } else  {
                    value = "false"
            elif pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value {
                // If the value type is CIM-TYPE-OBJECT, the EncodedValue is a HeapRef to the object encoded as an
                // ObjectEncodingLength (section 2.2.4) followed by an ObjectBlock (section 2.2.5).

                // ToDo: This is a hack.. We should parse this better. We need to have an ENCODING_UNIT.
                // I'm going through a METHOD_SIGNATURE_BLOCK first just to parse the ObjectBlock
                msb = METHOD_SIGNATURE_BLOCK(heapData)
                unit = ENCODING_UNIT()
                unit["ObjectEncodingLength"] = msb["EncodingLength"]
                unit["ObjectBlock"] = msb["ObjectBlock"]
                value = unit
            elif pType not in (CIM_TYPE_ENUM.CIM_TYPE_STRING.value, CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value,
                               CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value):
                value = entry
            } else  {
                try:
                    value = ENCODED_STRING(heapData)["Character"]
                except UnicodeDecodeError:
                    if logging.getLogger().level == logging.DEBUG {
                        LOG.debug("Unicode Error: dumping heapData")
                        hexdump(heapData)
                    raise

            return value

// 2.2.64 QualifierValue
QUALIFIER_VALUE = ENCODED_VALUE

// 2.2.60 Qualifier
 type QUALIFIER struct { // Structure:
    commonHdr = (
        ('QualifierName', QUALIFIER_NAME),
        ('QualifierFlavor', QUALIFIER_FLAVOR),
        ('QualifierType', QUALIFIER_TYPE),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self, data, alignment)
        if data is not nil {
            // Let's first check the commonHdr
            self.fromString(data)
            self. (('QualifierValue', CIM_TYPES_REF[self.QualifierType & (~CIM_ARRAY_FLAG)]),)
            self.fromString(data)
        } else  {
            self.data = nil

// 2.2.59 QualifierSet
 type QUALIFIER_SET struct { // Structure: (
        ('EncodingLength', ENCODING_LENGTH),
        ('_Qualifier','_-Qualifier', 'self.EncodingLength-4'),
        ('Qualifier', ':'),
    }

     func (self TYPE) getQualifiers(heap interface{}){
        data = self.Qualifier
        qualifiers = dict()
        while len(data) > 0:
            itemn = QUALIFIER(data)
            if itemn["QualifierName"] == 0xffffffff {
                qName = b''
            elif itemn["QualifierName"] & 0x80000000 {
                qName = DICTIONARY_REFERENCE[itemn["QualifierName"] & 0x7fffffff]
            } else  {
                qName = ENCODED_STRING(heap[itemn["QualifierName"]:])["Character"]

            value = ENCODED_VALUE.getValue(itemn["QualifierType"], itemn["QualifierValue"], heap)
            qualifiers[qName] = value
            data = data[len(itemn):]

        return qualifiers
 
// 2.2.20 ClassQualifierSet
CLASS_QUALIFIER_SET = QUALIFIER_SET

// 2.2.22 PropertyCount
PROPERTY_COUNT = "<L=0"

// 2.2.24 PropertyNameRef
PROPERTY_NAME_REF = HEAP_STRING_REF

// 2.2.25 PropertyInfoRef
PROPERTY_INFO_REF = HEAPREF

// 2.2.23 PropertyLookup
 type PropertyLookup struct { // Structure: (
        ('PropertyNameRef', PROPERTY_NAME_REF),
        ('PropertyInfoRef', PROPERTY_INFO_REF),
    }

// 2.2.31 PropertyType
PROPERTY_TYPE = "<L=0"

// 2.2.33 DeclarationOrder
DECLARATION_ORDER = "<H=0"

// 2.2.34 ValueTableOffset
VALUE_TABLE_OFFSET = "<L=0"

// 2.2.35 ClassOfOrigin
CLASS_OF_ORIGIN = "<L=0"

// 2.2.36 PropertyQualifierSet
PROPERTY_QUALIFIER_SET = QUALIFIER_SET

// 2.2.30 PropertyInfo
 type PROPERTY_INFO struct { // Structure: (
        ('PropertyType', PROPERTY_TYPE),
        ('DeclarationOrder', DECLARATION_ORDER),
        ('ValueTableOffset', VALUE_TABLE_OFFSET),
        ('ClassOfOrigin', CLASS_OF_ORIGIN),
        ('PropertyQualifierSet', ':', PROPERTY_QUALIFIER_SET),
    }

// 2.2.32 Inherited
Inherited = 0x4000

// 2.2.21 PropertyLookupTable
 type PROPERTY_LOOKUP_TABLE struct { // Structure:
    PropertyLookupSize = len(PropertyLookup()) (
        ('PropertyCount', PROPERTY_COUNT),
        ('_PropertyLookup','_-PropertyLookup', 'self.PropertyCount*self.PropertyLookupSize'),
        ('PropertyLookup', ':'),
    }

     func (self TYPE) getProperties(heap interface{}){
        propTable = self.PropertyLookup
        properties = dict()
        for property in range(self.PropertyCount):
            propItemDict = dict()
            propItem = PropertyLookup(propTable)
            if propItem["PropertyNameRef"] & 0x80000000 {
                propName = DICTIONARY_REFERENCE[propItem["PropertyNameRef"] & 0x7fffffff]
            } else  {
                propName = ENCODED_STRING(heap[propItem["PropertyNameRef"]:])["Character"]
            propInfo = PROPERTY_INFO(heap[propItem["PropertyInfoRef"]:])
            pType = propInfo["PropertyType"]
            pType &= (~CIM_ARRAY_FLAG)
            pType &= (~Inherited)
            sType = CIM_TYPE_TO_NAME[pType]
 
            propItemDict["stype"] = sType
            propItemDict["name"] = propName
            propItemDict["type"] = propInfo["PropertyType"]
            propItemDict["order"] = propInfo["DeclarationOrder"]
            propItemDict["inherited"] = propInfo["PropertyType"] & Inherited
            propItemDict["value"] = nil

            qualifiers = dict() 
            qualifiersBuf = propInfo["PropertyQualifierSet"]["Qualifier"]
            while len(qualifiersBuf) > 0:
                record = QUALIFIER(qualifiersBuf)
                if record["QualifierName"] & 0x80000000 {
                    qualifierName = DICTIONARY_REFERENCE[record["QualifierName"] & 0x7fffffff]
                } else  {
                    qualifierName = ENCODED_STRING(heap[record["QualifierName"]:])["Character"]
                qualifierValue = ENCODED_VALUE.getValue(record["QualifierType"], record["QualifierValue"], heap)
                qualifiersBuf = qualifiersBuf[len(record):]
                qualifiers[qualifierName] = qualifierValue

            propItemDict["qualifiers"] = qualifiers
            properties[propName] = propItemDict

            propTable = propTable[self.PropertyLookupSize:]

        return OrderedDict(sorted(list(properties.items()), key=lambda x:x[1]["order"]))
        //return properties

// 2.2.66 Heap
HEAP_LENGTH = "<L=0"

 type HEAP struct { // Structure: (
        ('HeapLength', HEAP_LENGTH),
        // HeapLength is a 32-bit value with the most significant bit always set 
        // (using little-endian binary encoding for the 32-bit value), so that the 
        // length is actually only 31 bits.
        ('_HeapItem','_-HeapItem', 'self.HeapLength&0x7fffffff'),
        ('HeapItem', ':'),
    }

// 2.2.37 ClassHeap
CLASS_HEAP = HEAP

// 2.2.15 ClassPart
 type CLASS_PART struct { // Structure:
    commonHdr = (
        ('ClassHeader', ':', CLASS_HEADER),
        ('DerivationList', ':', DERIVATION_LIST),
        ('ClassQualifierSet', ':', CLASS_QUALIFIER_SET),
        ('PropertyLookupTable', ':', PROPERTY_LOOKUP_TABLE),
        ('_NdTable_ValueTable','_-NdTable_ValueTable', 'self.ClassHeader"]["NdTableValueTableLength'),
        ('NdTable_ValueTable',':'),
        ('ClassHeap', ':', CLASS_HEAP),
        ('_Garbage', '_-Garbage', 'self.ClassHeader"]["EncodingLength-len(self)'),
        ('Garbage', ':=b""'),
    }
     func (self TYPE) getQualifiers(){
        return self.ClassQualifierSet"].getQualifiers(self["ClassHeap"]["HeapItem)

     func (self TYPE) getProperties(){
        heap = self.ClassHeap"]["HeapItem
        properties =  self.PropertyLookupTable"].getProperties(self["ClassHeap"]["HeapItem)
        sorted_props = sorted(list(properties.keys()), key=lambda k: properties[k]["order"])
        valueTableOff = (len(properties) - 1) // 4 + 1
        valueTable = self.NdTable_ValueTable[valueTableOff:]
        for key in sorted_props:
            // Let's get the default Values
            pType = properties[key]["type"] & (~(CIM_ARRAY_FLAG|Inherited))
            if properties[key]["type"] & CIM_ARRAY_FLAG {
                unpackStr = HEAPREF[:-2]
            } else  {
                unpackStr = CIM_TYPES_REF[pType][:-2]
            dataSize = calcsize(unpackStr)
            try:
                itemValue = unpack(unpackStr, valueTable[:dataSize])[0]
            except: 
                LOG.error("getProperties: Error unpacking!!")
                itemValue = 0xffffffff

            if itemValue != 0xffffffff and itemValue > 0 {
                value = ENCODED_VALUE.getValue(properties[key]["type"], itemValue, heap)
                properties[key]["value"] = "%s" % value
            valueTable = valueTable[dataSize:]
        return properties
             
// 2.2.39 MethodCount
METHOD_COUNT = "<H=0"

// 2.2.40 MethodCountPadding
METHOD_COUNT_PADDING = "<H=0"

// 2.2.42 MethodName
METHOD_NAME = HEAP_STRING_REF

// 2.2.43 MethodFlags
METHOD_FLAGS = "B=0"

// 2.2.44 MethodPadding
METHOD_PADDING = "3s=b''"

// 2.2.45 MethodOrigin
METHOD_ORIGIN = "<L=0"

// 2.2.47 HeapQualifierSetRef
HEAP_QUALIFIER_SET_REF = HEAPREF

// 2.2.46 MethodQualifiers
METHOD_QUALIFIERS = HEAP_QUALIFIER_SET_REF

// 2.2.51 HeapMethodSignatureBlockRef
HEAP_METHOD_SIGNATURE_BLOCK_REF = HEAPREF

// 2.2.50 MethodSignature
METHOD_SIGNATURE = HEAP_METHOD_SIGNATURE_BLOCK_REF

// 2.2.48 InputSignature
INPUT_SIGNATURE = METHOD_SIGNATURE

// 2.2.49 OutputSignature
OUTPUT_SIGNATURE = METHOD_SIGNATURE

// 2.2.52 MethodHeap
METHOD_HEAP = HEAP

// 2.2.41 MethodDescription
 type METHOD_DESCRIPTION struct { // Structure: (
        ('MethodName',METHOD_NAME),
        ('MethodFlags', METHOD_FLAGS),
        ('MethodPadding', METHOD_PADDING),
        ('MethodOrigin', METHOD_ORIGIN),
        ('MethodQualifiers', METHOD_QUALIFIERS),
        ('InputSignature', INPUT_SIGNATURE),
        ('OutputSignature', OUTPUT_SIGNATURE),
    }

// 2.2.38 MethodsPart
 type METHODS_PART struct { // Structure:
    MethodDescriptionSize = len(METHOD_DESCRIPTION()) (
        ('EncodingLength',ENCODING_LENGTH),
        ('MethodCount', METHOD_COUNT),
        ('MethodCountPadding', METHOD_COUNT_PADDING),
        ('_MethodDescription', '_-MethodDescription', 'self.MethodCount*self.MethodDescriptionSize'),
        ('MethodDescription', ':'),
        ('MethodHeap', ':', METHOD_HEAP),
    }

     func (self TYPE) getMethods(){
        methods = OrderedDict()
        data = self.MethodDescription
        heap = self.MethodHeap"]["HeapItem

        for method in range(self.MethodCount):
            methodDict = OrderedDict()
            itemn = METHOD_DESCRIPTION(data)
            if itemn["MethodFlags"] & WBEM_FLAVOR_ORIGIN_PROPAGATED {
               // ToDo
               //print "WBEM_FLAVOR_ORIGIN_PROPAGATED not yet supported!"
               //raise
               pass
            methodDict["name"] = ENCODED_STRING(heap[itemn["MethodName"]:])["Character"]
            methodDict["origin"] = itemn["MethodOrigin"]
            if itemn["MethodQualifiers"] != 0xffffffff {
                // There are qualifiers
                qualifiersSet = QUALIFIER_SET(heap[itemn["MethodQualifiers"]:])
                qualifiers = qualifiersSet.getQualifiers(heap)
                methodDict["qualifiers"] = qualifiers
            if itemn["InputSignature"] != 0xffffffff {
                inputSignature = METHOD_SIGNATURE_BLOCK(heap[itemn["InputSignature"]:])
                if inputSignature["EncodingLength"] > 0 {
                    methodDict["InParams"] = inputSignature["ObjectBlock"]["ClassType"]["CurrentClass"].getProperties()
                    methodDict["InParamsRaw"] = inputSignature["ObjectBlock"]
                    //print methodDict["InParams"] 
                } else  {
                    methodDict["InParams"] = nil
            if itemn["OutputSignature"] != 0xffffffff {
                outputSignature = METHOD_SIGNATURE_BLOCK(heap[itemn["OutputSignature"]:])
                if outputSignature["EncodingLength"] > 0 {
                    methodDict["OutParams"] = outputSignature["ObjectBlock"]["ClassType"]["CurrentClass"].getProperties()
                    methodDict["OutParamsRaw"] = outputSignature["ObjectBlock"]
                } else  {
                    methodDict["OutParams"] = nil
            data = data[len(itemn):]
            methods[methodDict["name"]] = methodDict

        return methods

// 2.2.14 ClassAndMethodsPart
 type CLASS_AND_METHODS_PART struct { // Structure: (
        ('ClassPart', ':', CLASS_PART),
        ('MethodsPart', ':', METHODS_PART),
    }

     func (self TYPE) getClassName(){
        pClassName = self.ClassPart"]["ClassHeader"]["ClassNameRef
        cHeap = self.ClassPart"]["ClassHeap"]["HeapItem
        if pClassName == 0xffffffff {
            return 'nil'
        } else  {
            className = ENCODED_STRING(cHeap[pClassName:])["Character"]
            derivationList = self.ClassPart"]["DerivationList"]["ClassNameEncoding
            while len(derivationList) > 0:
                superClass = ENCODED_STRING(derivationList)["Character"]
                className += ' : %s ' % superClass
                derivationList = derivationList[len(ENCODED_STRING(derivationList))+4:]
            return className

     func (self TYPE) getQualifiers(){
        return self.ClassPart.getQualifiers()

     func (self TYPE) getProperties(){
        //print format_structure(self.ClassPart.getProperties())
        return self.ClassPart.getProperties()

     func (self TYPE) getMethods(){
        return self.MethodsPart.getMethods()

// 2.2.13 CurrentClass
CURRENT_CLASS = CLASS_AND_METHODS_PART

// 2.2.54 InstanceFlags
INSTANCE_FLAGS = "B=0"

// 2.2.55 InstanceClassName
INSTANCE_CLASS_NAME = HEAP_STRING_REF

// 2.2.27 NullAndDefaultFlag
NULL_AND_DEFAULT_FLAG = "B=0"

// 2.2.26 NdTable
NDTABLE = NULL_AND_DEFAULT_FLAG

// 2.2.56 InstanceData
//InstanceData = ValueTable

 type CURRENT_CLASS_NO_METHODS struct { // CLASS_AND_METHODS_PART: (
        ('ClassPart', ':', CLASS_PART),
    }
     func (self TYPE) getMethods(){
        return ()

// 2.2.65 InstancePropQualifierSet
INST_PROP_QUAL_SET_FLAG = "B=0"
 type INSTANCE_PROP_QUALIFIER_SET struct { // Structure:
    commonHdr = (
        ('InstPropQualSetFlag', INST_PROP_QUAL_SET_FLAG),
    }
    tail = (
        // ToDo: this is wrong.. this should be an array of QualifierSet, see documentation
        //('QualifierSet', ':', QualifierSet),
        ('QualifierSet', ':', QUALIFIER_SET),
    }

     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self, data, alignment)
        self. ()
        if data is not nil {
            // Let's first check the commonHdr
            self.fromString(data)
            if self.InstPropQualSetFlag == 2 {
                // We don't support this yet!
                raise Exception("self.InstPropQualSetFlag == 2")
            self.fromString(data)
        } else  {
            self.data = nil

// 2.2.57 InstanceQualifierSet
 type INSTANCE_QUALIFIER_SET struct { // Structure: (
        ('QualifierSet', ':', QUALIFIER_SET),
        ('InstancePropQualifierSet', ':', INSTANCE_PROP_QUALIFIER_SET),
    }

// 2.2.58 InstanceHeap
INSTANCE_HEAP = HEAP

// 2.2.53 InstanceType
 type INSTANCE_TYPE struct { // Structure:
    commonHdr = (
        ('CurrentClass', ':', CURRENT_CLASS_NO_METHODS),
        ('EncodingLength', ENCODING_LENGTH),
        ('InstanceFlags', INSTANCE_FLAGS),
        ('InstanceClassName', INSTANCE_CLASS_NAME),
        ('_NdTable_ValueTable', '_-NdTable_ValueTable',
         'self.CurrentClass"]["ClassPart"]["ClassHeader"]["NdTableValueTableLength'),
        ('NdTable_ValueTable',':'),
        ('InstanceQualifierSet', ':', INSTANCE_QUALIFIER_SET),
        ('InstanceHeap', ':', INSTANCE_HEAP),
    }

     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self, data, alignment)
        self. ()
        if data is not nil {
            // Let's first check the commonHdr
            self.fromString(data)
            //hexdump(data[len(self.getData()):])
            self.NdTableSize = (self.CurrentClass"]["ClassPart"]["PropertyLookupTable"]["PropertyCount - 1) //4 + 1
            //self.InstanceDataSize = self.CurrentClass"]["ClassPart"]["PropertyLookupTable"]["PropertyCount * len(InstanceData())
            self.fromString(data)
        } else  {
            self.data = nil

     func (self TYPE) getValues(properties interface{}){
        heap = self.InstanceHeap"]["HeapItem
        valueTableOff = (len(properties) - 1) // 4 + 1
        valueTable = self.NdTable_ValueTable[valueTableOff:]
        sorted_props = sorted(list(properties.keys()), key=lambda k: properties[k]["order"])
        for key in sorted_props:
            pType = properties[key]["type"] & (~(CIM_ARRAY_FLAG|Inherited))
            if properties[key]["type"] & CIM_ARRAY_FLAG {
                unpackStr = HEAPREF[:-2]
            } else  {
                unpackStr = CIM_TYPES_REF[pType][:-2]
            dataSize = calcsize(unpackStr)
            try:
                itemValue = unpack(unpackStr, valueTable[:dataSize])[0]
            except:
                LOG.error("getValues: Error Unpacking!")
                itemValue = 0xffffffff

            // if itemValue == 0, default value remains
            if itemValue != 0 {
                value = ENCODED_VALUE.getValue( properties[key]["type"], itemValue, heap)
            } else  {
                value = 0
            properties[key]["value"] = value
            valueTable = valueTable[dataSize:] 
        return properties

// 2.2.12 ParentClass
PARENT_CLASS = CLASS_AND_METHODS_PART

// 2.2.13 CurrentClass
CURRENT_CLASS = CLASS_AND_METHODS_PART

 type CLASS_TYPE struct { // Structure: (
        ('ParentClass', ':', PARENT_CLASS),
        ('CurrentClass', ':', CURRENT_CLASS),
    }

// 2.2.5 ObjectBlock
 type OBJECT_BLOCK struct { // Structure:
    commonHdr = (
        ('ObjectFlags', OBJECT_FLAGS),
    }

    decoration = (
        ('Decoration', ':', DECORATION),
    }

    instanceType = (
        ('InstanceType', ':', INSTANCE_TYPE),
    }

    classType = (
        ('ClassType', ':', CLASS_TYPE),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self, data, alignment)
        self.ctParent  = nil
        self.ctCurrent = nil

        if data is not nil {
            self. ()
            if ord(data[0:1]) & 0x4 {
                // WMIO - 2.2.6 - 0x04 If this flag is set, the object has a Decoration block.
                self.structure += self.decoration
            if ord(data[0:1]) & 0x01 {
                // The object is a CIM class. 
                self.structure += self.classType
            } else  {
                self.structure += self.instanceType

            self.fromString(data)
        } else  {
            self.data = nil

     func (self TYPE) isInstance(){
        if self.ObjectFlags & 0x01 {
            return false
        return true

     func (self TYPE) printClass(pClass, cInstance = nil interface{}){
        qualifiers = pClass.getQualifiers()

        for qualifier in qualifiers:
            print("[%s]" % qualifier)

        className = pClass.getClassName()

        print(" type %s \n{" % className) struct {

        properties = pClass.getProperties()
        if cInstance is not nil {
            properties = cInstance.getValues(properties)

        for pName in properties:
            //if property["inherited"] == 0 {
                qualifiers = properties[pName]["qualifiers"]
                for qName in qualifiers:
                    if qName != 'CIMTYPE' {
                        print('\t[%s(%s)]' % (qName, qualifiers[qName]))
                print("\t%s %s" % (properties[pName]["stype"], properties[pName]["name"]), end=' ')
                if properties[pName]["value"] is not nil {
                    if properties[pName]["type"] == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value {
                        print("= IWbemClassObject\n")
                    elif properties[pName]["type"] == CIM_TYPE_ENUM.CIM_ARRAY_OBJECT.value {
                        if properties[pName]["value"] == 0 {
                            print('= %s\n' % properties[pName]["value"])
                        } else  {
                            print('= %s\n' % list('IWbemClassObject' for _ in range(len(properties[pName]["value"]))))
                    } else  {
                        print('= %s\n' % properties[pName]["value"])
                } else  {
                    print("\n")

        print() 
        methods = pClass.getMethods()
        for methodName in methods:
            for qualifier in methods[methodName]["qualifiers"]:
                print('\t[%s]' % qualifier)

            if methods[methodName]["InParams"] == nil and methods[methodName]["OutParams"] == nil { 
                print('\t%s %s();\n' % ('void', methodName))
            if methods[methodName]["InParams"] == nil and len(methods[methodName]["OutParams"]) == 1 {
                print('\t%s %s();\n' % (methods[methodName]["OutParams"]["ReturnValue"]["stype"], methodName))
            } else  {
                returnValue = b''
                if methods[methodName]["OutParams"] is not nil {
                    // Search the Return Value
                    //returnValue = (item for item in method["OutParams"] if item["name"] == "ReturnValue").next()
                    if 'ReturnValue' in methods[methodName]["OutParams"] {
                        returnValue = methods[methodName]["OutParams"]["ReturnValue"]["stype"]
 
                print('\t%s %s(\n' % (returnValue, methodName), end=' ')
                if methods[methodName]["InParams"] is not nil {
                    for pName  in methods[methodName]["InParams"]:
                        print('\t\t[in]    %s %s,' % (methods[methodName]["InParams"][pName]["stype"], pName))

                if methods[methodName]["OutParams"] is not nil {
                    for pName in methods[methodName]["OutParams"]:
                        if pName != 'ReturnValue' {
                            print('\t\t[out]    %s %s,' % (methods[methodName]["OutParams"][pName]["stype"], pName))

                print("\t);\n")

        print("}")

     func (self TYPE) parseClass(pClass, cInstance = nil interface{}){
        classDict = OrderedDict()
        classDict["name"] = pClass.getClassName()
        classDict["qualifiers"] = pClass.getQualifiers()
        classDict["properties"] = pClass.getProperties()
        classDict["methods"] = pClass.getMethods()
        if cInstance is not nil {
            classDict["values"] = cInstance.getValues(classDict["properties"])
        } else  {
            classDict["values"] = nil

        return classDict

     func (self TYPE) parseObject(){
        if (self.ObjectFlags & 0x01) == 0 {
            // instance
            ctCurrent = self.InstanceType"]["CurrentClass
            currentName = ctCurrent.getClassName()
            if currentName is not nil {
                self.ctCurrent = self.parseClass(ctCurrent, self.InstanceType)
            return
        } else  { 
            ctParent = self.ClassType"]["ParentClass
            ctCurrent = self.ClassType"]["CurrentClass

            parentName = ctParent.getClassName()
            if parentName is not nil {
                self.ctParent = self.parseClass(ctParent)

            currentName = ctCurrent.getClassName()
            if currentName is not nil {
                self.ctCurrent = self.parseClass(ctCurrent)

     func (self TYPE) printInformation(){
        // First off, do we have a class?
        if (self.ObjectFlags & 0x01) == 0 {
            // instance
            ctCurrent = self.InstanceType"]["CurrentClass
            currentName = ctCurrent.getClassName()
            if currentName is not nil {
                self.printClass(ctCurrent, self.InstanceType)
            return
        } else  { 
            ctParent = self.ClassType"]["ParentClass
            ctCurrent = self.ClassType"]["CurrentClass

            parentName = ctParent.getClassName()
            if parentName is not nil {
                self.printClass(ctParent)

            currentName = ctCurrent.getClassName()
            if currentName is not nil {
                self.printClass(ctCurrent)

// 2.2.70 MethodSignatureBlock
 type METHOD_SIGNATURE_BLOCK struct { // Structure:
    commonHdr = (
        ('EncodingLength', ENCODING_LENGTH),
    }
    tail = (
        ('_ObjectBlock', '_-ObjectBlock', 'self.EncodingLength'),
        ('ObjectBlock', ':', OBJECT_BLOCK),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self, data, alignment)
        if data is not nil {
            self.fromString(data)
            if self.EncodingLength > 0 {
                self. ()
                self.structure += self.tail
            self.fromString(data)
        } else  {
            self.data = nil

// 2.2.1 EncodingUnit
 type ENCODING_UNIT struct { // Structure: (
        ('Signature', SIGNATURE),
        ('ObjectEncodingLength', OBJECT_ENCODING_LENGTH),
        ('_ObjectBlock', '_-ObjectBlock', 'self.ObjectEncodingLength'),
        ('ObjectBlock', ':', OBJECT_BLOCK),
    }

//###############################################################################
// CONSTANTS
//###############################################################################
// 1.9 Standards Assignments
CLSID_WbemLevel1Login     = string_to_bin("8BC3F05E-D86B-11D0-A075-00C04FB68820")
CLSID_WbemBackupRestore   = string_to_bin("C49E32C6-BC8B-11D2-85D4-00105A1F8304")
CLSID_WbemClassObject     = string_to_bin("4590F812-1D3A-11D0-891F-00AA004B2E24")

IID_IWbemLevel1Login      = uuidtup_to_bin(('F309AD18-D86A-11d0-A075-00C04FB68820', '0.0'))
IID_IWbemLoginClientID    = uuidtup_to_bin(('d4781cd6-e5d3-44df-ad94-930efe48a887', '0.0'))
IID_IWbemLoginHelper      = uuidtup_to_bin(('541679AB-2E5F-11d3-B34E-00104BCC4B4A', '0.0'))
IID_IWbemServices         = uuidtup_to_bin(('9556DC99-828C-11CF-A37E-00AA003240C7', '0.0'))
IID_IWbemBackupRestore    = uuidtup_to_bin(('C49E32C7-BC8B-11d2-85D4-00105A1F8304', '0.0'))
IID_IWbemBackupRestoreEx  = uuidtup_to_bin(('A359DEC5-E813-4834-8A2A-BA7F1D777D76', '0.0'))
IID_IWbemClassObject      = uuidtup_to_bin(('DC12A681-737F-11CF-884D-00AA004B2E24', '0.0'))
IID_IWbemContext          = uuidtup_to_bin(('44aca674-e8fc-11d0-a07c-00c04fb68820', '0.0'))
IID_IEnumWbemClassObject  = uuidtup_to_bin(('027947e1-d731-11ce-a357-000000000001', '0.0'))
IID_IWbemCallResult       = uuidtup_to_bin(('44aca675-e8fc-11d0-a07c-00c04fb68820', '0.0'))
IID_IWbemFetchSmartEnum   = uuidtup_to_bin(('1C1C45EE-4395-11d2-B60B-00104B703EFD', '0.0'))
IID_IWbemWCOSmartEnum     = uuidtup_to_bin(('423EC01E-2E35-11d2-B604-00104B703EFD', '0.0'))

error_status_t = ULONG

// lFlags
WBEM_FLAG_RETURN_WBEM_COMPLETE          = 0x00000000
WBEM_FLAG_UPDATE_ONLY                   = 0x00000001
WBEM_FLAG_CREATE_ONLY                   = 0x00000002
WBEM_FLAG_RETURN_IMMEDIATELY            = 0x00000010
WBEM_FLAG_UPDATE_SAFE_MODE              = 0x00000020
WBEM_FLAG_FORWARD_ONLY                  = 0x00000020
WBEM_FLAG_NO_ERROR_OBJECT               = 0x00000040
WBEM_FLAG_UPDATE_FORCE_MODE             = 0x00000040
WBEM_FLAG_SEND_STATUS                   = 0x00000080
WBEM_FLAG_ENSURE_LOCATABLE              = 0x00000100
WBEM_FLAG_DIRECT_READ                   = 0x00000200
WBEM_MASK_RESERVED_FLAGS                = 0x0001F000
WBEM_FLAG_USE_AMENDED_QUALIFIERS        = 0x00020000
WBEM_FLAG_STRONG_VALIDATION             = 0x00100000
WBEM_FLAG_BACKUP_RESTORE_FORCE_SHUTDOWN = 0x00000001

WBEM_INFINITE = 0xffffffff

//###############################################################################
// STRUCTURES
//###############################################################################
 type UCHAR_ARRAY_CV struct { // NDRUniConformantVaryingArray:
    item = "c"

 type PUCHAR_ARRAY_CV struct { // NDRPOINTER:
    referent = (
        ('Data', UCHAR_ARRAY_CV),
    }

 type PMInterfacePointer_ARRAY_CV struct { // NDRUniConformantVaryingArray:
    item = PMInterfacePointer

REFGUID = PGUID

 type ULONG_ARRAY struct { // NDRUniConformantArray:
    item = ULONG

 type PULONG_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', ULONG_ARRAY),
    }

// 2.2.5 WBEM_CHANGE_FLAG_TYPE Enumeration
 type WBEM_CHANGE_FLAG_TYPE struct { // NDRENUM:
    // [v1_enum] type (
         Data uint32 // 
    }
     type enumItems struct { // Enum:
        WBEM_FLAG_CREATE_OR_UPDATE  = 0x00
        WBEM_FLAG_UPDATE_ONLY       = 0x01
        WBEM_FLAG_CREATE_ONLY       = 0x02
        WBEM_FLAG_UPDATE_SAFE_MODE  = 0x20
        WBEM_FLAG_UPDATE_FORCE_MODE = 0x40

// 2.2.6 WBEM_GENERIC_FLAG_TYPE Enumeration
 type WBEM_GENERIC_FLAG_TYPE struct { // NDRENUM:
    // [v1_enum] type (
         Data uint32 // 
    }
     type enumItems struct { // Enum:
        WBEM_FLAG_RETURN_WBEM_COMPLETE   = 0x00
        WBEM_FLAG_RETURN_IMMEDIATELY     = 0x10
        WBEM_FLAG_FORWARD_ONLY           = 0x20
        WBEM_FLAG_NO_ERROR_OBJECT        = 0x40
        WBEM_FLAG_SEND_STATUS            = 0x80
        WBEM_FLAG_ENSURE_LOCATABLE       = 0x100
        WBEM_FLAG_DIRECT_READ            = 0x200
        WBEM_MASK_RESERVED_FLAGS         = 0x1F000
        WBEM_FLAG_USE_AMENDED_QUALIFIERS = 0x20000
        WBEM_FLAG_STRONG_VALIDATION      = 0x100000

// 2.2.7 WBEM_STATUS_TYPE Enumeration
 type WBEM_STATUS_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        WBEM_STATUS_COMPLETE     = 0x00
        WBEM_STATUS_REQUIREMENTS = 0x01
        WBEM_STATUS_PROGRESS     = 0x02

// 2.2.8 WBEM_TIMEOUT_TYPE Enumeration
 type WBEM_TIMEOUT_TYPE struct { // NDRENUM:
    // [v1_enum] type (
         Data uint32 // 
    }
     type enumItems struct { // Enum:
        WBEM_NO_WAIT  = 0x00000000
        WBEM_INFINITE = 0xFFFFFFFF

// 2.2.9 WBEM_QUERY_FLAG_TYPE Enumeration
 type WBEM_QUERY_FLAG_TYPE struct { // NDRENUM:
    // [v1_enum] type (
         Data uint32 // 
    }
     type enumItems struct { // Enum:
        WBEM_FLAG_DEEP      = 0x00000000
        WBEM_FLAG_SHALLOW   = 0x00000001
        WBEM_FLAG_PROTOTYPE = 0x00000002

// 2.2.10 WBEM_BACKUP_RESTORE_FLAGS Enumeration
 type WBEM_BACKUP_RESTORE_FLAGS struct { // NDRENUM:
    // [v1_enum] type (
         Data uint32 // 
    }
     type enumItems struct { // Enum:
        WBEM_FLAG_BACKUP_RESTORE_FORCE_SHUTDOWN = 0x00000001

// 2.2.11 WBEMSTATUS Enumeration
 type WBEMSTATUS struct { // NDRENUM:
    // [v1_enum] type (
         Data uint32 // 
    }
     type enumItems struct { // Enum:
        WBEM_S_NO_ERROR                      = 0x00000000
        WBEM_S_FALSE                         = 0x00000001
        WBEM_S_TIMEDOUT                      = 0x00040004
        WBEM_S_NEW_STYLE                     = 0x000400FF
        WBEM_S_PARTIAL_RESULTS               = 0x00040010
        WBEM_E_FAILED                        = 0x80041001
        WBEM_E_NOT_FOUND                     = 0x80041002
        WBEM_E_ACCESS_DENIED                 = 0x80041003
        WBEM_E_PROVIDER_FAILURE              = 0x80041004
        WBEM_E_TYPE_MISMATCH                 = 0x80041005
        WBEM_E_OUT_OF_MEMORY                 = 0x80041006
        WBEM_E_INVALID_CONTEXT               = 0x80041007
        WBEM_E_INVALID_PARAMETER             = 0x80041008
        WBEM_E_NOT_AVAILABLE                 = 0x80041009
        WBEM_E_CRITICAL_ERROR                = 0x8004100a
        WBEM_E_NOT_SUPPORTED                 = 0x8004100c
        WBEM_E_PROVIDER_NOT_FOUND            = 0x80041011
        WBEM_E_INVALID_PROVIDER_REGISTRATION = 0x80041012
        WBEM_E_PROVIDER_LOAD_FAILURE         = 0x80041013
        WBEM_E_INITIALIZATION_FAILURE        = 0x80041014
        WBEM_E_TRANSPORT_FAILURE             = 0x80041015
        WBEM_E_INVALID_OPERATION             = 0x80041016
        WBEM_E_ALREADY_EXISTS                = 0x80041019
        WBEM_E_UNEXPECTED                    = 0x8004101d
        WBEM_E_INCOMPLETE_CLASS              = 0x80041020
        WBEM_E_SHUTTING_DOWN                 = 0x80041033
        E_NOTIMPL                            = 0x80004001
        WBEM_E_INVALID_SUPERCLASS            = 0x8004100D
        WBEM_E_INVALID_NAMESPACE             = 0x8004100E
        WBEM_E_INVALID_OBJECT                = 0x8004100F
        WBEM_E_INVALID_CLASS                 = 0x80041010
        WBEM_E_INVALID_QUERY                 = 0x80041017
        WBEM_E_INVALID_QUERY_TYPE            = 0x80041018
        WBEM_E_PROVIDER_NOT_CAPABLE          = 0x80041024
        WBEM_E_CLASS_HAS_CHILDREN            = 0x80041025
        WBEM_E_CLASS_HAS_INSTANCES           = 0x80041026
        WBEM_E_ILLEGAL_NULL                  = 0x80041028
        WBEM_E_INVALID_CIM_TYPE              = 0x8004102D
        WBEM_E_INVALID_METHOD                = 0x8004102E
        WBEM_E_INVALID_METHOD_PARAMETERS     = 0x8004102F
        WBEM_E_INVALID_PROPERTY              = 0x80041031
        WBEM_E_CALL_CANCELLED                = 0x80041032
        WBEM_E_INVALID_OBJECT_PATH           = 0x8004103A
        WBEM_E_OUT_OF_DISK_SPACE             = 0x8004103B
        WBEM_E_UNSUPPORTED_PUT_EXTENSION     = 0x8004103D
        WBEM_E_QUOTA_VIOLATION               = 0x8004106c
        WBEM_E_SERVER_TOO_BUSY               = 0x80041045
        WBEM_E_METHOD_NOT_IMPLEMENTED        = 0x80041055
        WBEM_E_METHOD_DISABLED               = 0x80041056
        WBEM_E_UNPARSABLE_QUERY              = 0x80041058
        WBEM_E_NOT_EVENT_CLASS               = 0x80041059
        WBEM_E_MISSING_GROUP_WITHIN          = 0x8004105A
        WBEM_E_MISSING_AGGREGATION_LIST      = 0x8004105B
        WBEM_E_PROPERTY_NOT_AN_OBJECT        = 0x8004105c
        WBEM_E_AGGREGATING_BY_OBJECT         = 0x8004105d
        WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING= 0x80041060
        WBEM_E_QUEUE_OVERFLOW                = 0x80041061
        WBEM_E_PRIVILEGE_NOT_HELD            = 0x80041062
        WBEM_E_INVALID_OPERATOR              = 0x80041063
        WBEM_E_CANNOT_BE_ABSTRACT            = 0x80041065
        WBEM_E_AMENDED_OBJECT                = 0x80041066
        WBEM_E_VETO_PUT                      = 0x8004107A
        WBEM_E_PROVIDER_SUSPENDED            = 0x80041081
        WBEM_E_ENCRYPTED_CONNECTION_REQUIRED = 0x80041087
        WBEM_E_PROVIDER_TIMED_OUT            = 0x80041088
        WBEM_E_NO_KEY                        = 0x80041089
        WBEM_E_PROVIDER_DISABLED             = 0x8004108a
        WBEM_E_REGISTRATION_TOO_BROAD        = 0x80042001
        WBEM_E_REGISTRATION_TOO_PRECISE      = 0x80042002

// 2.2.12 WBEM_CONNECT_OPTIONS Enumeration
 type WBEM_CONNECT_OPTIONS struct { // NDRENUM:
    // [v1_enum] type (
         Data uint32 // 
    }
     type enumItems struct { // Enum:
        WBEM_FLAG_CONNECT_REPOSITORY_ONLY = 0x40
        WBEM_FLAG_CONNECT_PROVIDERS       = 0x100

// 2.2.14 ObjectArray Structure
 type ObjectArray struct { // Structure: (
         dwByteOrdering uint32 // =0
         abSignature [8]byte // ="WBEMDATA"
         dwSizeOfHeader1 uint32 // =0x1a
         dwDataSize1 uint32 // =0
         dwFlags uint32 // =0
        ('bVersion', 'B=1'),
        ('bPacketType', 'B=0'),
         dwSizeOfHeader2 uint32 // =8
         dwDataSize2 uint32 // ', 'len(self.wbemObjects)+12
         dwSizeOfHeader3 uint32 // =12
         dwDataSize3 uint32 // ', 'len(self.dwDataSize2)-12)
         dwNumObjects uint32 // =0
        ('_wbemObjects', '_-wbemObjects', 'self.dwDataSize3'),
        ('wbemObjects', ':'),
    }

// 2.2.14.1 WBEM_DATAPACKET_OBJECT Structure
 type WBEM_DATAPACKET_OBJECT struct { // Structure: (
         dwSizeOfHeader uint32 // =9
         dwSizeOfData uint32 // ','len(self.Object)
        ('bObjectType', 'B=0'),
        ('_Object', '_-Object', 'self.dwSizeOfData'),
        ('Object', ':'),
    }

// 2.2.14.2 WBEMOBJECT_CLASS Structure
 type WBEMOBJECT_CLASS struct { // Structure: (
         dwSizeOfHeader uint32 // =8
         dwSizeOfData uint32 // ','len(self.ObjectData)
        ('_ObjectData', '_-ObjectData', 'self.dwSizeOfData'),
        ('ObjectData', ':'),
    }

// 2.2.14.3 WBEMOBJECT_INSTANCE Structure
 type WBEMOBJECT_INSTANCE struct { // Structure: (
         dwSizeOfHeader uint32 // =0x18
         dwSizeOfData uint32 // ','len(self.ObjectData)
         classID [6]byte // =b"\x00"*16
        ('_ObjectData', '_-ObjectData', 'self.dwSizeOfData'),
        ('ObjectData', ':'),
    }

// 2.2.14.4 WBEMOBJECT_INSTANCE_NOCLASS Structure
 type WBEMOBJECT_INSTANCE_NOCLASS struct { // Structure: (
         dwSizeOfHeader uint32 // =0x18
         dwSizeOfData uint32 // ','len(self.ObjectData)
         classID [6]byte // =b"\x00"*16
        ('_ObjectData', '_-ObjectData', 'self.dwSizeOfData'),
        ('ObjectData', ':'),
    }

// 2.2.15 WBEM_REFRESHED_OBJECT Structure
 type WBEM_REFRESHED_OBJECT struct { // NDRSTRUCT: (
        ('m_lRequestId', LONG),
        ('m_lBlobType', LONG),
        ('m_lBlobLength', LONG),
        ('m_pBlob', BYTE_ARRAY),
    }

 type WBEM_REFRESHED_OBJECT_ARRAY struct { // NDRUniConformantArray:
    item = WBEM_REFRESHED_OBJECT

 type PWBEM_REFRESHED_OBJECT_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', WBEM_REFRESHED_OBJECT_ARRAY),
    }

// 2.2.16 WBEM_INSTANCE_BLOB Enumeration
 type WBEM_INSTANCE_BLOB struct { // Structure: (
         Version uint32 // =0x1
         numObjects uint32 // =0
        ('Objects', ':'),
    }

// 2.2.17 WBEM_INSTANCE_BLOB_TYPE Enumeration
 type WBEM_INSTANCE_BLOB_TYPE struct { // NDRENUM:
    // [v1_enum] type (
         Data uint32 // 
    }
     type enumItems struct { // Enum:
        WBEM_FLAG_CONNECT_REPOSITORY_ONLY = 0x40
        WBEM_FLAG_CONNECT_PROVIDERS       = 0x100

// 2.2.26 _WBEM_REFRESH_INFO_NON_HIPERF Structure
 type _WBEM_REFRESH_INFO_NON_HIPERF struct { // NDRSTRUCT: (
        ('m_wszNamespace', LPWSTR),
        ('m_pTemplate', PMInterfacePointer),
    }

// 2.2.27 _WBEM_REFRESH_INFO_REMOTE Structure
 type _WBEM_REFRESH_INFO_REMOTE struct { // NDRSTRUCT: (
        ('m_pRefresher', PMInterfacePointer),
        ('m_pTemplate', PMInterfacePointer),
        ('m_Guid', GUID),
    }

// 2.2.25 WBEM_REFRESH_TYPE Enumeration
 type WBEM_REFRESH_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        WBEM_REFRESH_TYPE_INVALID       = 0
        WBEM_REFRESH_TYPE_REMOTE        = 3
        WBEM_REFRESH_TYPE_NON_HIPERF    = 6

// 2.2.28 _WBEM_REFRESH_INFO_UNION Union
 type _WBEM_REFRESH_INFO_UNION struct { // NDRUNION:
    commonHdr = (
        ('tag', LONG),
    }
    union = {
        WBEM_REFRESH_TYPE.WBEM_REFRESH_TYPE_REMOTE    : ('m_Remote', _WBEM_REFRESH_INFO_REMOTE),
        WBEM_REFRESH_TYPE.WBEM_REFRESH_TYPE_NON_HIPERF: ('m_NonHiPerf', _WBEM_REFRESH_INFO_NON_HIPERF),
        WBEM_REFRESH_TYPE.WBEM_REFRESH_TYPE_INVALID   : ('m_hres', HRESULT),
    }

// 2.2.20 _WBEM_REFRESH_INFO Structure
 type _WBEM_REFRESH_INFO struct { // NDRSTRUCT: (
        ('m_lType', LONG),
        ('m_Info', _WBEM_REFRESH_INFO_UNION),
        ('m_lCancelId', LONG),
    }

// 2.2.21 _WBEM_REFRESHER_ID Structure
 type _WBEM_REFRESHER_ID struct { // NDRSTRUCT: (
        ('m_szMachineName', LPCSTR),
        ('m_dwProcessId', DWORD),
        ('m_guidRefresherId', GUID),
    }

// 2.2.22 _WBEM_RECONNECT_INFO Structure
 type _WBEM_RECONNECT_INFO struct { // NDRSTRUCT: (
        ('m_lType', LPCSTR),
        ('m_pwcsPath', LPWSTR),
    }

 type _WBEM_RECONNECT_INFO_ARRAY struct { // NDRUniConformantArray:
    item = _WBEM_RECONNECT_INFO

// 2.2.23 _WBEM_RECONNECT_RESULTS Structure
 type _WBEM_RECONNECT_RESULTS struct { // NDRSTRUCT: (
        ('m_lId', LONG),
        ('m_hr', HRESULT),
    }

 type _WBEM_RECONNECT_RESULTS_ARRAY struct { // NDRUniConformantArray:
    item = _WBEM_RECONNECT_INFO


//###############################################################################
// RPC CALLS
//###############################################################################
// 3.1.4.1 IWbemLevel1Login Interface
// 3.1.4.1.1 IWbemLevel1Login::EstablishPosition (Opnum 3)
 type IWbemLevel1Login_EstablishPosition struct { // DCOMCALL:
    opnum = 3 (
       ('reserved1', LPWSTR),
       ('reserved2', DWORD),
    }

 type IWbemLevel1Login_EstablishPositionResponse struct { // DCOMANSWER: (
       ('LocaleVersion', DWORD),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.1.2 IWbemLevel1Login::RequestChallenge (Opnum 4)
 type IWbemLevel1Login_RequestChallenge struct { // DCOMCALL:
    opnum = 4 (
       ('reserved1', LPWSTR),
       ('reserved2', LPWSTR),
    }

 type IWbemLevel1Login_RequestChallengeResponse struct { // DCOMANSWER: (
       ('reserved3', UCHAR_ARRAY_CV),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.1.3 IWbemLevel1Login::WBEMLogin (Opnum 5)
 type IWbemLevel1Login_WBEMLogin struct { // DCOMCALL:
    opnum = 5 (
       ('reserved1', LPWSTR),
       ('reserved2', PUCHAR_ARRAY_CV),
       ('reserved3', LONG),
       ('reserved4', PMInterfacePointer),
    }

 type IWbemLevel1Login_WBEMLoginResponse struct { // DCOMANSWER: (
       ('reserved5', UCHAR_ARRAY_CV),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.1.4 IWbemLevel1Login::NTLMLogin (Opnum 6)
 type IWbemLevel1Login_NTLMLogin struct { // DCOMCALL:
    opnum = 6 (
       ('wszNetworkResource', LPWSTR),
       ('wszPreferredLocale', LPWSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    }

 type IWbemLevel1Login_NTLMLoginResponse struct { // DCOMANSWER: (
       ('ppNamespace', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2 IWbemObjectSink Interface Server Details
// 3.1.4.2.1 IWbemObjectSink::Indicate (Opnum 3) Server details
 type IWbemObjectSink_Indicate struct { // DCOMCALL:
    opnum = 3 (
       ('lObjectCount', LONG),
       ('apObjArray', PMInterfacePointer_ARRAY),
    }

 type IWbemObjectSink_IndicateResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2.2 IWbemObjectSink::SetStatus (Opnum 4) Server Details
 type IWbemObjectSink_SetStatus struct { // DCOMCALL:
    opnum = 4 (
       ('lFlags', LONG),
       ('hResult', HRESULT),
       ('strParam', BSTR),
       ('pObjParam', PMInterfacePointer),
    }

 type IWbemObjectSink_SetStatusResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3 IWbemServices Interface
// 3.1.4.3.1 IWbemServices::OpenNamespace (Opnum 3)
 type IWbemServices_OpenNamespace struct { // DCOMCALL:
    opnum = 3 (
       ('strNamespace', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppWorkingNamespace', PMInterfacePointer),
       ('ppResult', PMInterfacePointer),
    }

 type IWbemServices_OpenNamespaceResponse struct { // DCOMANSWER: (
       ('ppWorkingNamespace', PPMInterfacePointer),
       ('ppResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.2 IWbemServices::CancelAsyncCall (Opnum 4)
 type IWbemServices_CancelAsyncCall struct { // DCOMCALL:
    opnum = 4 (
       ('IWbemObjectSink', PMInterfacePointer),
    }

 type IWbemServices_CancelAsyncCallResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.3 IWbemServices::QueryObjectSink (Opnum 5)
 type IWbemServices_QueryObjectSink struct { // DCOMCALL:
    opnum = 5 (
       ('lFlags', LONG),
    }

 type IWbemServices_QueryObjectSinkResponse struct { // DCOMANSWER: (
       ('ppResponseHandler', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.4 IWbemServices::GetObject (Opnum 6)
 type IWbemServices_GetObject struct { // DCOMCALL:
    opnum = 6 (
       ('strObjectPath', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppObject', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    }

 type IWbemServices_GetObjectResponse struct { // DCOMANSWER: (
       ('ppObject', PPMInterfacePointer),
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.5 IWbemServices::GetObjectAsync (Opnum 7)
 type IWbemServices_GetObjectAsync struct { // DCOMCALL:
    opnum = 7 (
       ('strObjectPath', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    }

 type IWbemServices_GetObjectAsyncResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.6 IWbemServices::PutClass (Opnum 8)
 type IWbemServices_PutClass struct { // DCOMCALL:
    opnum = 8 (
       ('pObject', PMInterfacePointer),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    }

 type IWbemServices_PutClassResponse struct { // DCOMANSWER: (
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.7 IWbemServices::PutClassAsync (Opnum 9)
 type IWbemServices_PutClassAsync struct { // DCOMCALL:
    opnum = 9 (
       ('pObject', PMInterfacePointer),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    }

 type IWbemServices_PutClassAsyncResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.8 IWbemServices::DeleteClass (Opnum 10)
 type IWbemServices_DeleteClass struct { // DCOMCALL:
    opnum = 10 (
       ('strClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    }

 type IWbemServices_DeleteClassResponse struct { // DCOMANSWER: (
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.9 IWbemServices::DeleteClassAsync (Opnum 11)
 type IWbemServices_DeleteClassAsync struct { // DCOMCALL:
    opnum = 11 (
       ('strClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    }

 type IWbemServices_DeleteClassAsyncResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.10 IWbemServices::CreateClassEnum (Opnum 12)
 type IWbemServices_CreateClassEnum struct { // DCOMCALL:
    opnum = 12 (
       ('strSuperClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    }

 type IWbemServices_CreateClassEnumResponse struct { // DCOMANSWER: (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.11 IWbemServices::CreateClassEnumAsync (Opnum 13)
 type IWbemServices_CreateClassEnumAsync struct { // DCOMCALL:
    opnum = 13 (
       ('strSuperClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    }

 type IWbemServices_CreateClassEnumAsyncResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.12 IWbemServices::PutInstance (Opnum 14)
 type IWbemServices_PutInstance struct { // DCOMCALL:
    opnum = 14 (
       ('pInst', PMInterfacePointer),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    }

 type IWbemServices_PutInstanceResponse struct { // DCOMANSWER: (
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.13 IWbemServices::PutInstanceAsync (Opnum 15)
 type IWbemServices_PutInstanceAsync struct { // DCOMCALL:
    opnum = 15 (
       ('pInst', PMInterfacePointer),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    }

 type IWbemServices_PutInstanceAsyncResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.14 IWbemServices::DeleteInstance (Opnum 16)
 type IWbemServices_DeleteInstance struct { // DCOMCALL:
    opnum = 16 (
       ('strObjectPath', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    }

 type IWbemServices_DeleteInstanceResponse struct { // DCOMANSWER: (
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.15 IWbemServices::DeleteInstanceAsync (Opnum 17)
 type IWbemServices_DeleteInstanceAsync struct { // DCOMCALL:
    opnum = 17 (
       ('strObjectPath', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    }

 type IWbemServices_DeleteInstanceAsyncResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.16 IWbemServices::CreateInstanceEnum (Opnum 18)
 type IWbemServices_CreateInstanceEnum struct { // DCOMCALL:
    opnum = 18 (
       ('strSuperClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    }

 type IWbemServices_CreateInstanceEnumResponse struct { // DCOMANSWER: (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.17 IWbemServices::CreateInstanceEnumAsync (Opnum 19)
 type IWbemServices_CreateInstanceEnumAsync struct { // DCOMCALL:
    opnum = 19 (
       ('strSuperClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    }

 type IWbemServices_CreateInstanceEnumAsyncResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.18 IWbemServices::ExecQuery (Opnum 20)
 type IWbemServices_ExecQuery struct { // DCOMCALL:
    opnum = 20 (
       ('strQueryLanguage', BSTR),
       ('strQuery', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    }

 type IWbemServices_ExecQueryResponse struct { // DCOMANSWER: (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.19 IWbemServices::ExecQueryAsync (Opnum 21)
 type IWbemServices_ExecQueryAsync struct { // DCOMCALL:
    opnum = 21 (
       ('strQueryLanguage', BSTR),
       ('strQuery', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    }

 type IWbemServices_ExecQueryAsyncResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.20 IWbemServices::ExecNotificationQuery (Opnum 22)
 type IWbemServices_ExecNotificationQuery struct { // DCOMCALL:
    opnum = 22 (
       ('strQueryLanguage', BSTR),
       ('strQuery', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    }

 type IWbemServices_ExecNotificationQueryResponse struct { // DCOMANSWER: (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.21 IWbemServices::ExecNotificationQueryAsync (Opnum 23)
 type IWbemServices_ExecNotificationQueryAsync struct { // DCOMCALL:
    opnum = 23 (
       ('strQueryLanguage', BSTR),
       ('strQuery', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    }

 type IWbemServices_ExecNotificationQueryAsyncResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.22 IWbemServices::ExecMethod (Opnum 24)
 type IWbemServices_ExecMethod struct { // DCOMCALL:
    opnum = 24 (
       ('strObjectPath', BSTR),
       ('strMethodName', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pInParams', PMInterfacePointer),
       ('ppOutParams', PPMInterfacePointer),
       ('ppCallResult', PPMInterfacePointer),
    }

 type IWbemServices_ExecMethodResponse struct { // DCOMANSWER: (
       ('ppOutParams', PPMInterfacePointer),
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.23 IWbemServices::ExecMethodAsync (Opnum 25)
 type IWbemServices_ExecMethodAsync struct { // DCOMCALL:
    opnum = 25 (
       ('strObjectPath', BSTR),
       ('strMethodName', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pInParams', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    }

 type IWbemServices_ExecMethodAsyncResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4 IEnumWbemClassObject Interface
// 3.1.4.4.1 IEnumWbemClassObject::Reset (Opnum 3)
 type IEnumWbemClassObject_Reset struct { // DCOMCALL:
    opnum = 3 (
    }

 type IEnumWbemClassObject_ResetResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.2 IEnumWbemClassObject::Next (Opnum 4)
 type IEnumWbemClassObject_Next struct { // DCOMCALL:
    opnum = 4 (
       ('lTimeout', ULONG),
       ('uCount', ULONG),
    }

 type IEnumWbemClassObject_NextResponse struct { // DCOMANSWER: (
       ('apObjects', PMInterfacePointer_ARRAY_CV),
       ('puReturned', ULONG),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.3 IEnumWbemClassObject::NextAsync (Opnum 5)
 type IEnumWbemClassObject_NextAsync struct { // DCOMCALL:
    opnum = 5 (
       ('lTimeout', LONG),
       ('pSink', PMInterfacePointer),
    }

 type IEnumWbemClassObject_NextAsyncResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.4 IEnumWbemClassObject::Clone (Opnum 6)
 type IEnumWbemClassObject_Clone struct { // DCOMCALL:
    opnum = 6 (
    }

 type IEnumWbemClassObject_CloneResponse struct { // DCOMANSWER: (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.5 IEnumWbemClassObject::Skip (Opnum 7)
 type IEnumWbemClassObject_Skip struct { // DCOMCALL:
    opnum = 7 (
       ('lTimeout', LONG),
       ('uCount', ULONG),
    }

 type IEnumWbemClassObject_SkipResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.5 IWbemCallResult Interface
// 3.1.4.5.1 IWbemCallResult::GetResultObject (Opnum 3)
 type IWbemCallResult_GetResultObject struct { // DCOMCALL:
    opnum = 3 (
       ('lTimeout', LONG),
    }

 type IWbemCallResult_GetResultObjectResponse struct { // DCOMANSWER: (
       ('ppResultObject', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.5.2 IWbemCallResult::GetResultString (Opnum 4)
 type IWbemCallResult_GetResultString struct { // DCOMCALL:
    opnum = 4 (
       ('lTimeout', LONG),
    }

 type IWbemCallResult_GetResultStringResponse struct { // DCOMANSWER: (
       ('pstrResultString', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.5.3 IWbemCallResult::GetResultServices (Opnum 5)
 type IWbemCallResult_GetResultServices struct { // DCOMCALL:
    opnum = 5 (
       ('lTimeout', LONG),
    }

 type IWbemCallResult_GetResultServicesResponse struct { // DCOMANSWER: (
       ('ppServices', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.5.4 IWbemCallResult::GetCallStatus (Opnum 6)
 type IWbemCallResult_GetCallStatus struct { // DCOMCALL:
    opnum = 6 (
       ('lTimeout', LONG),
    }

 type IWbemCallResult_GetCallStatusResponse struct { // DCOMANSWER: (
       ('plStatus', LONG),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.6 IWbemFetchSmartEnum Interface
// 3.1.4.6.1 IWbemFetchSmartEnum::GetSmartEnum (Opnum 3)
 type IWbemFetchSmartEnum_GetSmartEnum struct { // DCOMCALL:
    opnum = 3 (
    }

 type IWbemFetchSmartEnum_GetSmartEnumResponse struct { // DCOMANSWER: (
       ('ppSmartEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.7 IWbemWCOSmartEnum Interface
// 3.1.4.7.1 IWbemWCOSmartEnum::Next (Opnum 3)
 type IWbemWCOSmartEnum_Next struct { // DCOMCALL:
    opnum = 3 (
       ('proxyGUID', REFGUID),
       ('lTimeout', LONG),
       ('uCount', ULONG),
    }

 type IWbemWCOSmartEnum_NextResponse struct { // DCOMANSWER: (
       ('puReturned', ULONG),
       ('pdwBuffSize', ULONG),
       ('pBuffer', BYTE_ARRAY),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.8 IWbemLoginClientID Interface
// 3.1.4.8.1 IWbemLoginClientID::SetClientInfo (Opnum 3)
 type IWbemLoginClientID_SetClientInfo struct { // DCOMCALL:
    opnum = 3 (
       ('wszClientMachine', LPWSTR),
       ('lClientProcId', LONG),
       ('lReserved', LONG),
    }

 type IWbemLoginClientID_SetClientInfoResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.9 IWbemLoginHelper Interface
// 3.1.4.9.1 IWbemLoginHelper::SetEvent (Opnum 3)
 type IWbemLoginHelper_SetEvent struct { // DCOMCALL:
    opnum = 3 (
       ('sEventToSet', LPCSTR),
    }

 type IWbemLoginHelper_SetEventResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
// 3.1.4.10 IWbemBackupRestore Interface
// 3.1.4.10.1 IWbemBackupRestore::Backup (Opnum 3)
 type IWbemBackupRestore_Backup struct { // DCOMCALL:
    opnum = 3 (
       ('strBackupToFile', LPWSTR),
       ('lFlags', LONG),
    }

 type IWbemBackupRestore_BackupResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.10.2 IWbemBackupRestore::Restore (Opnum 4)
 type IWbemBackupRestore_Restore struct { // DCOMCALL:
    opnum = 4 (
       ('strRestoreFromFile', LPWSTR),
       ('lFlags', LONG),
    }

 type IWbemBackupRestore_RestoreResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.11 IWbemBackupRestoreEx Interface
// 3.1.4.11.1 IWbemBackupRestoreEx::Pause (Opnum 5)
 type IWbemBackupRestoreEx_Pause struct { // DCOMCALL:
    opnum = 5 (
    }

 type IWbemBackupRestoreEx_PauseResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.11.2 IWbemBackupRestoreEx::Resume (Opnum 6)
 type IWbemBackupRestoreEx_Resume struct { // DCOMCALL:
    opnum = 6 (
    }

 type IWbemBackupRestoreEx_ResumeResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.12 IWbemRefreshingServices Interface
// 3.1.4.12.1 IWbemRefreshingServices::AddObjectToRefresher (Opnum 3)
 type IWbemRefreshingServices_AddObjectToRefresher struct { // DCOMCALL:
    opnum = 3 (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('wszPath', LPWSTR),
       ('lFlags', LONG),
       ('pContext', PMInterfacePointer),
       ('dwClientRefrVersion', DWORD),
    }

 type IWbemRefreshingServices_AddObjectToRefresherResponse struct { // DCOMANSWER: (
       ('pInfo', _WBEM_REFRESH_INFO),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.12.2 IWbemRefreshingServices::AddObjectToRefresherByTemplate (Opnum 4)
 type IWbemRefreshingServices_AddObjectToRefresherByTemplate struct { // DCOMCALL:
    opnum = 4 (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('pTemplate', PMInterfacePointer),
       ('lFlags', LONG),
       ('pContext', PMInterfacePointer),
       ('dwClientRefrVersion', DWORD),
    }

 type IWbemRefreshingServices_AddObjectToRefresherByTemplateResponse struct { // DCOMANSWER: (
       ('pInfo', _WBEM_REFRESH_INFO),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.12.3 IWbemRefreshingServices::AddEnumToRefresher (Opnum 5)
 type IWbemRefreshingServices_AddEnumToRefresher struct { // DCOMCALL:
    opnum = 5 (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('wszClass', LPWSTR),
       ('lFlags', LONG),
       ('pContext', PMInterfacePointer),
       ('dwClientRefrVersion', DWORD),
    }

 type IWbemRefreshingServices_AddEnumToRefresherResponse struct { // DCOMANSWER: (
       ('pInfo', _WBEM_REFRESH_INFO),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.12.4 IWbemRefreshingServices::RemoveObjectFromRefresher (Opnum 6)
 type IWbemRefreshingServices_RemoveObjectFromRefresher struct { // DCOMCALL:
    opnum = 6 (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('lId', LONG),
       ('lFlags', LONG),
       ('dwClientRefrVersion', DWORD),
    }

 type IWbemRefreshingServices_RemoveObjectFromRefresherResponse struct { // DCOMANSWER: (
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.12.5 IWbemRefreshingServices::GetRemoteRefresher (Opnum 7)
 type IWbemRefreshingServices_GetRemoteRefresher struct { // DCOMCALL:
    opnum = 7 (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('lFlags', LONG),
       ('dwClientRefrVersion', DWORD),
    }

 type IWbemRefreshingServices_GetRemoteRefresherResponse struct { // DCOMANSWER: (
       ('ppRemRefresher', PMInterfacePointer),
       ('pGuid', GUID),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.12.6 IWbemRefreshingServices::ReconnectRemoteRefresher (Opnum 8)
 type IWbemRefreshingServices_ReconnectRemoteRefresher struct { // DCOMCALL:
    opnum = 8 (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('lFlags', LONG),
       ('lNumObjects', LONG),
       ('dwClientRefrVersion', DWORD),
       ('apReconnectInfo', _WBEM_RECONNECT_INFO_ARRAY),
    }

 type IWbemRefreshingServices_ReconnectRemoteRefresherResponse struct { // DCOMANSWER: (
       ('apReconnectResults', _WBEM_RECONNECT_RESULTS_ARRAY),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.13 IWbemRemoteRefresher Interface
// 3.1.4.13.1 IWbemRemoteRefresher::RemoteRefresh (Opnum 3)
 type IWbemRemoteRefresher_RemoteRefresh struct { // DCOMCALL:
    opnum = 3 (
       ('lFlags', LONG),
    }

 type IWbemRemoteRefresher_RemoteRefreshResponse struct { // DCOMANSWER: (
       ('plNumObjects', _WBEM_RECONNECT_RESULTS_ARRAY),
       ('paObjects', PWBEM_REFRESHED_OBJECT_ARRAY),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.13.2 IWbemRemoteRefresher::StopRefreshing (Opnum 4)
 type IWbemRemoteRefresher_StopRefreshing struct { // DCOMCALL:
    opnum = 4 (
       ('lNumIds', LONG),
       ('aplIds', PULONG_ARRAY),
       ('lFlags', LONG),
    }

 type IWbemRemoteRefresher_StopRefreshingResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.14 IWbemShutdown Interface
// 3.1.4.14.1 IWbemShutdown::Shutdown (Opnum 3)
 type IWbemShutdown_Shutdown struct { // DCOMCALL:
    opnum = 3 (
       ('reserved1', LONG),
       ('reserved2', ULONG),
       ('reserved3', PMInterfacePointer),
    }

 type IWbemShutdown_ShutdownResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.15 IUnsecuredApartment Interface
// 3.1.4.15.1 IUnsecuredApartment::CreateObjectStub (Opnum 3)
 type IUnsecuredApartment_CreateObjectStub struct { // DCOMCALL:
    opnum = 3 (
       ('reserved1', PMInterfacePointer),
    }

 type IUnsecuredApartment_CreateObjectStubResponse struct { // DCOMANSWER: (
       ('reserved2', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.16 IWbemUnsecuredApartment Interface
// 3.1.4.16.1 IWbemUnsecuredApartment::CreateSinkStub (Opnum 3)
 type IWbemUnsecuredApartment_CreateSinkStub struct { // DCOMCALL:
    opnum = 3 (
       ('reserved1', PMInterfacePointer),
       ('reserved2', DWORD),
       ('reserved3', LPWSTR),
    }

 type IWbemUnsecuredApartment_CreateSinkStubResponse struct { // DCOMANSWER: (
       ('reserved4', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
}

//###############################################################################
// HELPER FUNCTIONS AND INTERFACES
//###############################################################################
 func checkNullString(string interface{}){
    if string == NULL {
        return string

    if string[-1:] != '\x00' {
        return string + '\x00'
    } else  {
        return string

 type IWbemClassObject struct { // IRemUnknown:
     func (self TYPE) __init__(interface, iWbemServices = nil interface{}){
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemClassObject
        self.__iWbemServices = iWbemServices
        self.__methods = nil

        objRef = self.get_objRef()
        objRef = OBJREF_CUSTOM(objRef)
        self.encodingUnit = ENCODING_UNIT(objRef["pObjectData"])
        self.parseObject()
        if self.encodingUnit["ObjectBlock"].isInstance() is false {
            self.createMethods(self.getClassName(), self.getMethods())
        } else  {
            self.createProperties(self.getProperties())

     func (self TYPE) __getattr__(attr interface{}){
        if attr.startswith("__") is not true {
            properties = self.getProperties()
            // Let's see if there's a key property so we can ExecMethod
            keyProperty = nil
            for pName in properties:
                if 'key' in properties[pName]["qualifiers"] {
                    keyProperty = pName

            if keyProperty == nil {
                LOG.error("I don't have a key property in this set!")
            } else  {
                if self.__methods == nil {
                    classObject,_ = self.__iWbemServices.GetObject(self.getClassName())
                    self.__methods = classObject.getMethods()

                if attr in self.__methods {
                    // Now we gotta build the  type name to be called through ExecMethod struct {
                    if self.getProperties()[keyProperty]["stype"] != 'string' {
                        instanceName = "%s.%s=%s" % (
                        self.getClassName(), keyProperty, self.getProperties()[keyProperty]["value"])
                    } else  {
                        instanceName = "%s.%s="%s"" % (
                        self.getClassName(), keyProperty, self.getProperties()[keyProperty]["value"])

                    self.createMethods(instanceName , self.__methods)
                    //print dir(self)
                    return getattr(self, attr)

        raise AttributeError("%r object has no attribute %r" %
                             (self.__class__, attr))

     func (self TYPE) parseObject(){
        self.encodingUnit["ObjectBlock"].parseObject()

     func (self TYPE) getObject(){
        return self.encodingUnit["ObjectBlock"]

     func (self TYPE) getClassName(){
        if self.encodingUnit["ObjectBlock"].isInstance() is false {
            return self.encodingUnit["ObjectBlock"]["ClassType"]["CurrentClass"].getClassName().split(" ")[0]
        } else  {
            return self.encodingUnit["ObjectBlock"]["InstanceType"]["CurrentClass"].getClassName().split(" ")[0]

     func (self TYPE) printInformation(){
        return self.encodingUnit["ObjectBlock"].printInformation()

     func (self TYPE) getProperties(){
        if self.encodingUnit["ObjectBlock"].ctCurrent == nil {
            return ()
        return self.encodingUnit["ObjectBlock"].ctCurrent["properties"]
    
     func (self TYPE) getMethods(){
        if self.encodingUnit["ObjectBlock"].ctCurrent == nil {
            return ()
        return self.encodingUnit["ObjectBlock"].ctCurrent["methods"]

     func (self TYPE) marshalMe(){
        // So, in theory, we have the OBJCUSTOM built, but 
        // we need to update the values
        // That's what we'll do

        instanceHeap = b''
        valueTable = b''
        ndTable = 0
        parametersClass = ENCODED_STRING()
        parametersClass["Character"] = self.getClassName()
        instanceHeap += parametersClass.getData()
        curHeapPtr = len(instanceHeap)
        properties = self.getProperties()
        for i, propName in enumerate(properties):
            propRecord = properties[propName]
            itemValue = getattr(self, propName)
            print("PropName %r, Value: %r" % (propName,itemValue))

            pType = propRecord["type"] & (~(CIM_ARRAY_FLAG|Inherited)) 
            if propRecord["type"] & CIM_ARRAY_FLAG {
                // Not yet ready
                packStr = HEAPREF[:-2]
            } else  {
                packStr = CIM_TYPES_REF[pType][:-2]

            if propRecord["type"] & CIM_ARRAY_FLAG {
                if itemValue == nil {
                    valueTable += pack(packStr, 0)
                } else  {
                    valueTable += pack('<L', curHeapPtr)
                    arraySize = pack(HEAPREF[:-2], len(itemValue))
                    packStrArray =  CIM_TYPES_REF[pType][:-2]
                    arrayItems = b''
                    for j in range(len(itemValue)):
                        arrayItems += pack(packStrArray, itemValue[j])
                    instanceHeap += arraySize + arrayItems
                    curHeapPtr = len(instanceHeap)
            elif pType not in (CIM_TYPE_ENUM.CIM_TYPE_STRING.value, CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value,
                               CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value, CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value):
                if itemValue == nil {
                    valueTable += pack(packStr, -1)
                } else  {
                    valueTable += pack(packStr, itemValue)
            elif pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value {
                // For now we just pack nil
                valueTable += b'\x00'*4
                // The default property value is NULL, and it is 
                // inherited from a parent class.
                if itemValue == nil {
                    ndTable |= 3 << (2*i)
            } else  {
                if itemValue is '' {
                    ndTable |= 1 << (2*i)
                    valueTable += pack('<L', 0)
                } else  {
                    strIn = ENCODED_STRING()
                    strIn["Character"] = itemValue
                    valueTable += pack('<L', curHeapPtr)
                    instanceHeap += strIn.getData()
                    curHeapPtr = len(instanceHeap)

        ndTableLen = (len(properties) - 1) // 4 + 1
        packedNdTable = b''
        for i in range(ndTableLen):
            packedNdTable += pack('B', ndTable & 0xff)
            ndTable >>=  8

        // Now let's update the structure
        objRef = self.get_objRef()
        objRef = OBJREF_CUSTOM(objRef)
        encodingUnit = ENCODING_UNIT(objRef["pObjectData"])

        currentClass = encodingUnit["ObjectBlock"]["InstanceType"]["CurrentClass"]
        encodingUnit["ObjectBlock"]["InstanceType"]["CurrentClass"] = b''

        encodingUnit["ObjectBlock"]["InstanceType"]["NdTable_ValueTable"] = packedNdTable + valueTable
        encodingUnit["ObjectBlock"]["InstanceType"]["InstanceHeap"]["HeapLength"] = len(instanceHeap) | 0x80000000
        encodingUnit["ObjectBlock"]["InstanceType"]["InstanceHeap"]["HeapItem"] = instanceHeap

        encodingUnit["ObjectBlock"]["InstanceType"]["EncodingLength"] = len(encodingUnit["ObjectBlock"]["InstanceType"])
        encodingUnit["ObjectBlock"]["InstanceType"]["CurrentClass"] = currentClass

        encodingUnit["ObjectEncodingLength"] = len(encodingUnit["ObjectBlock"])

        //encodingUnit.dump()
        //ENCODING_UNIT(str(encodingUnit)).dump()

        objRef["pObjectData"] = encodingUnit

        return objRef

     func (self TYPE) SpawnInstance(){
        // Doing something similar to:
        // https://docs.microsoft.com/windows/desktop/api/wbemcli/nf-wbemcli-iwbemclassobject-spawninstance
        //
        if self.encodingUnit["ObjectBlock"].isInstance() is false {
            // We need to convert some things to transform a  type into an instance struct {
            encodingUnit = ENCODING_UNIT()

            instanceData = OBJECT_BLOCK()
            instanceData.structure += OBJECT_BLOCK.decoration
            instanceData.structure += OBJECT_BLOCK.instanceType
            instanceData["ObjectFlags"] = 6
            instanceData["Decoration"] = self.encodingUnit["ObjectBlock"]["Decoration"].getData()

            instanceType = INSTANCE_TYPE()
            instanceType["CurrentClass"] = b''

            // Let's create the heap for the parameters
            instanceHeap = b''
            valueTable = b''
            parametersClass = ENCODED_STRING()
            parametersClass["Character"] = self.getClassName()
            instanceHeap += parametersClass.getData()
            curHeapPtr = len(instanceHeap)

            ndTable = 0
            properties = self.getProperties()

            // Let's initialize the values
            for i, propName in enumerate(properties):
                propRecord = properties[propName]

                pType = propRecord["type"] & (~(CIM_ARRAY_FLAG|Inherited)) 
                if propRecord["type"] & CIM_ARRAY_FLAG {
                    // Not yet ready
                    //print paramDefinition
                    //raise
                    packStr = HEAPREF[:-2]
                } else  {
                    packStr = CIM_TYPES_REF[pType][:-2]

                if propRecord["type"] & CIM_ARRAY_FLAG {
                    valueTable += pack(packStr, 0)
                elif pType not in (CIM_TYPE_ENUM.CIM_TYPE_STRING.value, CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value,
                                   CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value, CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value):
                    valueTable += pack(packStr, 0)
                elif pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value {
                    // For now we just pack nil
                    valueTable += b'\x00'*4
                    // The default property value is NULL, and it is 
                    // inherited from a parent class.
                    ndTable |= 3 << (2*i)
                } else  {
                    strIn = ENCODED_STRING()
                    strIn["Character"] = ""
                    valueTable += pack('<L', curHeapPtr)
                    instanceHeap += strIn.getData()
                    curHeapPtr = len(instanceHeap)

            ndTableLen = (len(properties) - 1) // 4 + 1
            packedNdTable = b''
            for i in range(ndTableLen):
                packedNdTable += pack('B', ndTable & 0xff)
                ndTable >>=  8

            instanceType["NdTable_ValueTable"] = packedNdTable + valueTable

            instanceType["InstanceQualifierSet"] = b'\x04\x00\x00\x00\x01'

            instanceType["InstanceHeap"] = HEAP()
            instanceType["InstanceHeap"]["HeapItem"] = instanceHeap
            instanceType["InstanceHeap"]["HeapLength"] = len(instanceHeap) | 0x80000000
            instanceType["EncodingLength"] = len(instanceType)

            instanceType["CurrentClass"] = self.encodingUnit["ObjectBlock"]["ClassType"]["CurrentClass"]["ClassPart"]
            instanceData["InstanceType"] = instanceType.getData()

            encodingUnit["ObjectBlock"] = instanceData
            encodingUnit["ObjectEncodingLength"] = len(instanceData)

            //ENCODING_UNIT(str(encodingUnit)).dump()

            objRefCustomIn = OBJREF_CUSTOM()
            objRefCustomIn["iid"] = self._iid
            objRefCustomIn["clsid"] = CLSID_WbemClassObject
            objRefCustomIn["cbExtension"] = 0
            objRefCustomIn["ObjectReferenceSize"] = len(encodingUnit)
            objRefCustomIn["pObjectData"] = encodingUnit

            // There's gotta be a better way to do this
            // I will reimplement this stuff once I know it works
            import copy
            newObj = copy.deepcopy(self)
            newObj.set_objRef(objRefCustomIn.getData())
            newObj.process_interface(objRefCustomIn.getData())
            newObj.encodingUnit = ENCODING_UNIT(encodingUnit.getData())
            newObj.parseObject()
            if newObj.encodingUnit["ObjectBlock"].isInstance() is false {
                newObj.createMethods(newObj.getClassName(), newObj.getMethods())
            } else  {
                newObj.createProperties(newObj.getProperties())

            return newObj
        } else  {
            return self

     func (self TYPE) createProperties(properties interface{}){
        for property in properties:
            // Do we have an object property?
            if properties[property]["type"] == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value {
                // Yes.. let's create an Object for it too
                objRef = OBJREF_CUSTOM()
                objRef["iid"] = self._iid
                objRef["clsid"] = CLSID_WbemClassObject
                objRef["cbExtension"] = 0
                objRef["ObjectReferenceSize"] = len(properties[property]["value"].getData())
                objRef["pObjectData"] = properties[property]["value"]
                value = IWbemClassObject( INTERFACE(self.get_cinstance(), objRef.getData(), self.get_ipidRemUnknown(),
                      oxid=self.get_oxid(), target=self.get_target()))
            elif properties[property]["type"] == CIM_TYPE_ENUM.CIM_ARRAY_OBJECT.value {
                if isinstance(properties[property]["value"], list) {
                    value = list()
                    for item in properties[property]["value"]:
                        // Yes.. let's create an Object for it too
                        objRef = OBJREF_CUSTOM()
                        objRef["iid"] = self._iid
                        objRef["clsid"] = CLSID_WbemClassObject
                        objRef["cbExtension"] = 0
                        objRef["ObjectReferenceSize"] = len(item.getData())
                        objRef["pObjectData"] = item
                        wbemClass = IWbemClassObject(
                            INTERFACE(self.get_cinstance(), objRef.getData(), self.get_ipidRemUnknown(),
                                      oxid=self.get_oxid(), target=self.get_target()))
                        value.append(wbemClass)
                } else  {
                    value = properties[property]["value"]
            } else  {
                value = properties[property]["value"]
            setattr(self, property, value)

     func (self TYPE) createMethods(classOrInstance, methods interface{}){
         type FunctionPool: struct {
             func __init__(self,function interface{}){
                self.function = function
             func __getitem__(self,item interface{}){
                return partial(self.function,item)

        @FunctionPool
         func innerMethod(staticArgs, *args interface{}){
            classOrInstance = staticArgs[0] 
            methodDefinition = staticArgs[1] 
            if methodDefinition["InParams"] is not nil {
                if len(args) != len(methodDefinition["InParams"]) {
                    LOG.error("Function called with %d parameters instead of %d!" % (len(args), len(methodDefinition["InParams"])))
                    return nil
                // In Params
                encodingUnit = ENCODING_UNIT()

                inParams = OBJECT_BLOCK()
                inParams.structure += OBJECT_BLOCK.instanceType
                inParams["ObjectFlags"] = 2
                inParams["Decoration"] = b''

                instanceType = INSTANCE_TYPE()
                instanceType["CurrentClass"] = b''
                instanceType["InstanceQualifierSet"] = b'\x04\x00\x00\x00\x01'

                // Let's create the heap for the parameters
                instanceHeap = b''
                valueTable = b''
                parametersClass = ENCODED_STRING()
                parametersClass["Character"] = "__PARAMETERS"
                instanceHeap += parametersClass.getData()
                curHeapPtr = len(instanceHeap)

                ndTable = 0
                for i in range(len(args)):
                    paramDefinition = list(methodDefinition["InParams"].values())[i]
                    inArg = args[i]

                    pType = paramDefinition["type"] & (~(CIM_ARRAY_FLAG|Inherited)) 
                    if paramDefinition["type"] & CIM_ARRAY_FLAG {
                        // Not yet ready
                        //print paramDefinition
                        //raise
                        packStr = HEAPREF[:-2]
                    } else  {
                        packStr = CIM_TYPES_REF[pType][:-2]

                    if paramDefinition["type"] & CIM_ARRAY_FLAG {
                        
                        if inArg == nil {
                            valueTable += pack(packStr, 0)
                        } else  {
                            // ToDo
                            // Not yet ready
                            raise Exception("inArg not nil")
                    elif pType not in (CIM_TYPE_ENUM.CIM_TYPE_STRING.value, CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value,
                                       CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value, CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value):
                        valueTable += pack(packStr, inArg)
                    elif pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value {
                        // For now we just pack nil
                        valueTable += b'\x00'*4
                        // The default property value is NULL, and it is 
                        // inherited from a parent class.
                        if inArg == nil {
                            ndTable |= 3 << (2*i)
                    } else  {
                        strIn = ENCODED_STRING()
                        if type(inArg) is str {
                            // The Encoded-String-Flag is set to 0x01 if the sequence of characters that follows
                            // consists of UTF-16 characters (as specified in [UNICODE]) followed by a UTF-16 null
                            // terminator.
                            strIn["Encoded_String_Flag"] = 0x1
                            strIn. strIn.tunicode
                            strIn["Character"] = inArg.encode("utf-16le")
                        } else  {
                            strIn["Character"] = inArg
                        valueTable += pack('<L', curHeapPtr)
                        instanceHeap += strIn.getData()
                        curHeapPtr = len(instanceHeap)

                ndTableLen = (len(args) - 1) // 4 + 1

                packedNdTable = b''
                for i in range(ndTableLen):
                    packedNdTable += pack('B', ndTable & 0xff)
                    ndTable >>=  8

                instanceType["NdTable_ValueTable"] = packedNdTable + valueTable
                heapRecord = HEAP()
                heapRecord["HeapLength"] = len(instanceHeap) | 0x80000000
                heapRecord["HeapItem"] = instanceHeap
                
                instanceType["InstanceHeap"] = heapRecord

                instanceType["EncodingLength"] = len(instanceType)
                inMethods = methodDefinition["InParamsRaw"]["ClassType"]["CurrentClass"]["ClassPart"]
                inMethods["ClassHeader"]["EncodingLength"] = len(
                    methodDefinition["InParamsRaw"]["ClassType"]["CurrentClass"]["ClassPart"].getData())
                instanceType["CurrentClass"] = inMethods

                inParams["InstanceType"] = instanceType.getData()

                encodingUnit["ObjectBlock"] = inParams
                encodingUnit["ObjectEncodingLength"] = len(inParams)

                objRefCustomIn = OBJREF_CUSTOM()
                objRefCustomIn["iid"] = self._iid
                objRefCustomIn["clsid"] = CLSID_WbemClassObject
                objRefCustomIn["cbExtension"] = 0
                objRefCustomIn["ObjectReferenceSize"] = len(encodingUnit)
                objRefCustomIn["pObjectData"] = encodingUnit
            } else  {
                objRefCustomIn = NULL

            //## OutParams
            encodingUnit = ENCODING_UNIT()

            outParams = OBJECT_BLOCK()
            outParams.structure += OBJECT_BLOCK.instanceType
            outParams["ObjectFlags"] = 2
            outParams["Decoration"] = b''

            instanceType = INSTANCE_TYPE()
            instanceType["CurrentClass"] = b''
            instanceType["NdTable_ValueTable"] = b''
            instanceType["InstanceQualifierSet"] = b''
            instanceType["InstanceHeap"] = b''
            instanceType["EncodingLength"] = len(instanceType)
            instanceType["CurrentClass"] = methodDefinition["OutParamsRaw"]["ClassType"]["CurrentClass"]["ClassPart"].getData()
            outParams["InstanceType"] = instanceType.getData()


            encodingUnit["ObjectBlock"] = outParams
            encodingUnit["ObjectEncodingLength"] = len(outParams)

            objRefCustom = OBJREF_CUSTOM()
            objRefCustom["iid"] = self._iid
            objRefCustom["clsid"] = CLSID_WbemClassObject
            objRefCustom["cbExtension"] = 0
            objRefCustom["ObjectReferenceSize"] = len(encodingUnit)
            objRefCustom["pObjectData"] = encodingUnit
            try:
                return self.__iWbemServices.ExecMethod(classOrInstance, methodDefinition["name"], pInParams = objRefCustomIn )
                //return self.__iWbemServices.ExecMethod('Win32_Process.Handle="436"', methodDefinition["name"],
                //                                       pInParams=objRefCustomIn).getObject().ctCurrent["properties"]
            except Exception as e:
                if LOG.level == logging.DEBUG {
                    import traceback
                    traceback.print_exc()
                LOG.error(str(e))

        for methodName in methods:
           innerMethod.__name__ = methodName
           setattr(self,innerMethod.__name__,innerMethod[classOrInstance,methods[methodName]])
        //methods = self.encodingUnit["ObjectBlock"]
 

 type IWbemLoginClientID struct { // IRemUnknown:
     func (self TYPE) __init__(interface interface{}){
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemLoginClientID

     func (self TYPE) SetClientInfo(wszClientMachine, lClientProcId = 1234 interface{}){
        request = IWbemLoginClientID_SetClientInfo()
        request["wszClientMachine"] = checkNullString(wszClientMachine)
        request["lClientProcId"] = lClientProcId
        request["lReserved"] = 0
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

 type IWbemLoginHelper struct { // IRemUnknown:
     func (self TYPE) __init__(interface interface{}){
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemLoginHelper

     func (self TYPE) SetEvent(sEventToSet interface{}){
        request = IWbemLoginHelper_SetEvent()
        request["sEventToSet"] = sEventToSet
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp


 type IWbemWCOSmartEnum struct { // IRemUnknown:
     func (self TYPE) __init__(interface interface{}){
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemWCOSmartEnum

     func (self TYPE) Next(proxyGUID, lTimeout, uCount interface{}){
        request = IWbemWCOSmartEnum_Next()
        request["proxyGUID"] = proxyGUID
        request["lTimeout"] = lTimeout
        request["uCount"] = uCount
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

 type IWbemFetchSmartEnum struct { // IRemUnknown:
     func (self TYPE) __init__(interface interface{}){
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemFetchSmartEnum

     func (self TYPE) GetSmartEnum(lTimeout interface{}){
        request = IWbemFetchSmartEnum_GetSmartEnum()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

 type IWbemCallResult struct { // IRemUnknown:
     func (self TYPE) __init__(interface interface{}){
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemCallResult

     func (self TYPE) GetResultObject(lTimeout interface{}){
        request = IWbemCallResult_GetResultObject()
        request["lTimeout"] = lTimeout
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) GetResultString(lTimeout interface{}){
        request = IWbemCallResult_GetResultString()
        request["lTimeout"] = lTimeout
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) GetResultServices(lTimeout interface{}){
        request = IWbemCallResult_GetResultServices()
        request["lTimeout"] = lTimeout
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) GetCallStatus(lTimeout interface{}){
        request = IWbemCallResult_GetCallStatus()
        request["lTimeout"] = lTimeout
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp["plStatus"]

 type IEnumWbemClassObject struct { // IRemUnknown:
     func (self TYPE) __init__(interface, iWbemServices = nil interface{}){
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IEnumWbemClassObject
        self.__iWbemServices = iWbemServices

     func (self TYPE) Reset(){
        request = IEnumWbemClassObject_Reset()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) Next(lTimeout, uCount interface{}){
        request = IEnumWbemClassObject_Next()
        request["lTimeout"] = lTimeout
        request["uCount"] = uCount
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        interfaces = list()
        for interface in resp["apObjects"]:
            interfaces.append(IWbemClassObject(
                INTERFACE(self.get_cinstance(), b''.join(interface["abData"]), self.get_ipidRemUnknown(),
                          oxid=self.get_oxid(), target=self.get_target()), self.__iWbemServices))

        return interfaces

     func (self TYPE) NextAsync(lTimeout, pSink interface{}){
        request = IEnumWbemClassObject_NextAsync()
        request["lTimeout"] = lTimeout
        request["pSink"] = pSink
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) Clone(){
        request = IEnumWbemClassObject_Clone()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) Skip(lTimeout, uCount interface{}){
        request = IEnumWbemClassObject_Skip()
        request["lTimeout"] = lTimeout
        request["uCount"] = uCount
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

 type IWbemServices struct { // IRemUnknown:
     func (self TYPE) __init__(interface interface{}){
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemServices

     func (self TYPE) OpenNamespace(strNamespace, lFlags=0, pCtx = NULL interface{}){
        request = IWbemServices_OpenNamespace()
        request["strNamespace"]["asData"] = strNamespace
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func CancelAsyncCall(self,IWbemObjectSink  interface{}){
        request = IWbemServices_CancelAsyncCall()
        request["IWbemObjectSink"] = IWbemObjectSink
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp["ErrorCode"]

     func (self TYPE) QueryObjectSink(){
        request = IWbemServices_QueryObjectSink()
        request["lFlags"] = 0
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return INTERFACE(self.get_cinstance(), b''.join(resp["ppResponseHandler"]["abData"]), self.get_ipidRemUnknown(),
                         target=self.get_target())

     func (self TYPE) GetObject(strObjectPath, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_GetObject()
        request["strObjectPath"]["asData"] = strObjectPath
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        ppObject = IWbemClassObject(
            INTERFACE(self.get_cinstance(), b''.join(resp["ppObject"]["abData"]), self.get_ipidRemUnknown(),
                      oxid=self.get_oxid(), target=self.get_target()), self)
        if resp["ppCallResult"] != NULL {
            ppcallResult = IWbemCallResult(
                INTERFACE(self.get_cinstance(), b''.join(resp["ppObject"]["abData"]), self.get_ipidRemUnknown(),
                          target=self.get_target()))
        } else  {
            ppcallResult = NULL
        return ppObject, ppcallResult

     func (self TYPE) GetObjectAsync(strNamespace, lFlags=0, pCtx = NULL interface{}){
        request = IWbemServices_GetObjectAsync()
        request["strObjectPath"]["asData"] = checkNullString(strNamespace)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) PutClass(pObject, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_PutClass()
        request["pObject"] = pObject
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) PutClassAsync(pObject, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_PutClassAsync()
        request["pObject"] = pObject
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) DeleteClass(strClass, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_DeleteClass()
        request["strClass"]["asData"] = checkNullString(strClass)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) DeleteClassAsync(strClass, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_DeleteClassAsync()
        request["strClass"]["asData"] = checkNullString(strClass)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) CreateClassEnum(strSuperClass, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_CreateClassEnum()
        request["strSuperClass"]["asData"] = checkNullString(strSuperClass)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) CreateClassEnumAsync(strSuperClass, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_CreateClassEnumAsync()
        request["strSuperClass"]["asData"] = checkNullString(strSuperClass)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) PutInstance(pInst, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_PutInstance()

        if pInst is NULL {
            request["pInst"] = pInst
        } else  {
            request["pInst"]["ulCntData"] = len(pInst)
            request["pInst"]["abData"] = list(pInst.getData())
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IWbemCallResult(
            INTERFACE(self.get_cinstance(), b''.join(resp["ppCallResult"]["abData"]), self.get_ipidRemUnknown(),
                      target=self.get_target()))

     func (self TYPE) PutInstanceAsync(pInst, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_PutInstanceAsync()
        request["pInst"] = pInst
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) DeleteInstance(strObjectPath, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_DeleteInstance()
        request["strObjectPath"]["asData"] = checkNullString(strObjectPath)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IWbemCallResult(
            INTERFACE(self.get_cinstance(), b''.join(resp["ppCallResult"]["abData"]), self.get_ipidRemUnknown(),
                      target=self.get_target()))

     func (self TYPE) DeleteInstanceAsync(strObjectPath, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_DeleteInstanceAsync()
        request["strObjectPath"]["asData"] = checkNullString(strObjectPath)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) CreateInstanceEnum(strSuperClass, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_CreateInstanceEnum()
        request["strSuperClass"]["asData"] = strSuperClass
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return IEnumWbemClassObject(
            INTERFACE(self.get_cinstance(), b''.join(resp["ppEnum"]["abData"]), self.get_ipidRemUnknown(),
                      target=self.get_target()))

     func (self TYPE) CreateInstanceEnumAsync(strSuperClass, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_CreateInstanceEnumAsync()
        request["strSuperClass"]["asData"] = checkNullString(strSuperClass)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    // func (self TYPE) ExecQuery(strQuery, lFlags=WBEM_QUERY_FLAG_TYPE.WBEM_FLAG_PROTOTYPE, pCtx=NULL interface{}){
     func (self TYPE) ExecQuery(strQuery, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_ExecQuery()
        request["strQueryLanguage"]["asData"] = checkNullString("WQL")
        request["strQuery"]["asData"] = checkNullString(strQuery)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IEnumWbemClassObject(
            INTERFACE(self.get_cinstance(), b''.join(resp["ppEnum"]["abData"]), self.get_ipidRemUnknown(),
                      target=self.get_target()), self)

     func (self TYPE) ExecQueryAsync(strQuery, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_ExecQueryAsync()
        request["strQueryLanguage"]["asData"] = checkNullString("WQL")
        request["strQuery"]["asData"] = checkNullString(strQuery)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) ExecNotificationQuery(strQuery, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_ExecNotificationQuery()
        request["strQueryLanguage"]["asData"] = checkNullString("WQL")
        request["strQuery"]["asData"] = checkNullString(strQuery)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IEnumWbemClassObject(
            INTERFACE(self.get_cinstance(), b''.join(resp["ppEnum"]["abData"]), self.get_ipidRemUnknown(),
                      target=self.get_target()), self)

     func (self TYPE) ExecNotificationQueryAsync(strQuery, lFlags=0, pCtx=NULL interface{}){
        request = IWbemServices_ExecNotificationQueryAsync()
        request["strQueryLanguage"]["asData"] = checkNullString("WQL")
        request["strQuery"]["asData"] = checkNullString(strQuery)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) ExecMethod(strObjectPath, strMethodName, lFlags=0, pCtx=NULL, pInParams=NULL, ppOutParams = NULL interface{}){
        request = IWbemServices_ExecMethod()
        request["strObjectPath"]["asData"] = checkNullString(strObjectPath)
        request["strMethodName"]["asData"] = checkNullString(strMethodName)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        if pInParams is NULL {
            request["pInParams"] = pInParams
        } else  {
            request["pInParams"]["ulCntData"] = len(pInParams)
            request["pInParams"]["abData"] = list(pInParams.getData())

        request.fields["ppCallResult"] = NULL
        if ppOutParams is NULL {
            request.fields["ppOutParams"].fields["Data"] = NULL
        } else  {
            request["ppOutParams"]["ulCntData"] = len(ppOutParams.getData())
            request["ppOutParams"]["abData"] = list(ppOutParams.getData())
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IWbemClassObject(
            INTERFACE(self.get_cinstance(), b''.join(resp["ppOutParams"]["abData"]), self.get_ipidRemUnknown(),
                      oxid=self.get_oxid(), target=self.get_target()))

     func (self TYPE) ExecMethodAsync(strObjectPath, strMethodName, lFlags=0, pCtx=NULL, pInParams=NULL interface{}){
        request = IWbemServices_ExecMethodAsync()
        request["strObjectPath"]["asData"] = checkNullString(strObjectPath)
        request["strMethodName"]["asData"] = checkNullString(strMethodName)
        request["lFlags"] = lFlags
        request["pCtx"] = pCtx
        request["pInParams"] = pInParams
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

 type IWbemLevel1Login struct { // IRemUnknown:
     func (self TYPE) __init__(interface interface{}){
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemLevel1Login

     func (self TYPE) EstablishPosition(){
        request = IWbemLevel1Login_EstablishPosition()
        request["reserved1"] = NULL
        request["reserved2"] = 0
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp["LocaleVersion"]

     func (self TYPE) RequestChallenge(){
        request = IWbemLevel1Login_RequestChallenge()
        request["reserved1"] = NULL
        request["reserved2"] = NULL
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp["reserved3"]

     func (self TYPE) WBEMLogin(){
        request = IWbemLevel1Login_WBEMLogin()
        request["reserved1"] = NULL
        request["reserved2"] = NULL
        request["reserved3"] = 0
        request["reserved4"] = NULL
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp["reserved5"]

     func (self TYPE) NTLMLogin(wszNetworkResource, wszPreferredLocale, pCtx interface{}){
        request = IWbemLevel1Login_NTLMLogin()
        request["wszNetworkResource"] = checkNullString(wszNetworkResource)
        request["wszPreferredLocale"] = checkNullString(wszPreferredLocale)
        request["lFlags"] = 0
        request["pCtx"] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IWbemServices(
            INTERFACE(self.get_cinstance(), b''.join(resp["ppNamespace"]["abData"]), self.get_ipidRemUnknown(),
                      target=self.get_target()))


if __name__ == '__main__' {
    // Example 1
    baseClass = b'xV4\x12\xd0\x00\x00\x00\x05\x00DPRAVAT-DEV\x00\x00ROOT\x00\x1d\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80f\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\n\x00\x00\x00\x05\xff\xff\xff\xff<\x00\x00\x80\x00Base\x00\x00Id\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x004\x00\x00\x00\x01\x00\x00\x80\x13\x0b\x00\x00\x00\xff\xff\x00sint32\x00\x0c\x00\x00\x00\x00\x004\x00\x00\x00\x00\x80\x00\x80\x13\x0b\x00\x00\x00\xff\xff\x00sint32\x00'

    //encodingUnit = ENCODING_UNIT(baseClass)
    //encodingUnit.dump()
    //encodingUnit["ObjectBlock"].printInformation()
    //print "LEN ", len(baseClass), len(encodingUnit)

    //myClass = b"xV4\x12.\x02\x00\x00\x05\x00DPRAVAT-DEV\x00\x00ROOT\x00f\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\n\x00\x00\x00\x05\xff\xff\xff\xff<\x00\x00\x80\x00Base\x00\x00Id\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x004\x00\x00\x00\x01\x00\x00\x80\x13\x0b\x00\x00\x00\xff\xff\x00sint32\x00\x0c\x00\x00\x00\x00\x004\x00\x00\x00\x00\x80v\x01\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x0e\x00\x00\x00\x00Base\x00\x06\x00\x00\x00\x11\x00\x00\x00\t\x00\x00\x00\x00\x08\x00\x00\x00\x16\x00\x00\x00\x04\x00\x00\x00'\x00\x00\x00.\x00\x00\x00U\x00\x00\x00\\\x00\x00\x00\x99\x00\x00\x00\xa0\x00\x00\x00\xc7\x00\x00\x00\xcb\x00\x00\x00G\xff\xff\xff\xff\xff\xff\xff\xff\xfd\x00\x00\x00\xff\xff\xff\xff\x11\x01\x00\x80\x00MyClass\x00\x00Description\x00\x00MyClass Example\x00\x00Array\x00\x13 \x00\x00\x03\x00\x0c\x00\x00\x00\x01\x00\x00\x00\x11\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00M\x00\x00\x00\x00uint32\x00\x00Data1\x00\x08\x00\x00\x00\x01\x00\x04\x00\x00\x00\x01\x00\x00\x00'\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\x91\x00\x00\x00\x03\x00\x00\x80\x00\x0b\x00\x00\x00\xff\xff\x04\x00\x00\x80\x00\x0b\x00\x00\x00\xff\xff\x00string\x00\x00Data2\x00\x08\x00\x00\x00\x02\x00\x08\x00\x00\x00\x01\x00\x00\x00\x11\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xbf\x00\x00\x00\x00string\x00\x00Id\x00\x03@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00\xf5\x00\x00\x00\x01\x00\x00\x803\x0b\x00\x00\x00\xff\xff\x00sint32\x00\x00defaultValue\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00s\x00\x00\x00\x802\x00\x00defaultValue\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00"
    //hexdump(myClass)
    //encodingUnit = ENCODING_UNIT(myClass)
    //print "LEN ", len(myClass), len(encodingUnit)
    //encodingUnit.dump()
    //encodingUnit["ObjectBlock"].printInformation()

    //instanceMyClass = b"xV4\x12\xd3\x01\x00\x00\x06\x00DPRAVAT-DEV\x00\x00ROOT\x00v\x01\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x0e\x00\x00\x00\x00Base\x00\x06\x00\x00\x00\x11\x00\x00\x00\t\x00\x00\x00\x00\x08\x00\x00\x00\x16\x00\x00\x00\x04\x00\x00\x00'\x00\x00\x00.\x00\x00\x00U\x00\x00\x00\\\x00\x00\x00\x99\x00\x00\x00\xa0\x00\x00\x00\xc7\x00\x00\x00\xcb\x00\x00\x00G\xff\xff\xff\xff\xff\xff\xff\xff\xfd\x00\x00\x00\xff\xff\xff\xff\x11\x01\x00\x80\x00MyClass\x00\x00Description\x00\x00MyClass Example\x00\x00Array\x00\x13 \x00\x00\x03\x00\x0c\x00\x00\x00\x01\x00\x00\x00\x11\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00M\x00\x00\x00\x00uint32\x00\x00Data1\x00\x08\x00\x00\x00\x01\x00\x04\x00\x00\x00\x01\x00\x00\x00'\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\x91\x00\x00\x00\x03\x00\x00\x80\x00\x0b\x00\x00\x00\xff\xff\x04\x00\x00\x80\x00\x0b\x00\x00\x00\xff\xff\x00string\x00\x00Data2\x00\x08\x00\x00\x00\x02\x00\x08\x00\x00\x00\x01\x00\x00\x00\x11\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xbf\x00\x00\x00\x00string\x00\x00Id\x00\x03@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00\xf5\x00\x00\x00\x01\x00\x00\x803\x0b\x00\x00\x00\xff\xff\x00sint32\x00\x00defaultValue\x00\x00\x00\x00\x00\x00\x00I\x00\x00\x00\x00\x00\x00\x00\x00 {\x00\x00\x00\x19\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x04\x00\x00\x00\x01&\x00\x00\x80\x00MyClass\x00\x03\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x00StringField\x00"
    //encodingUnit = ENCODING_UNIT(instanceMyClass)
    //encodingUnit.dump()
    //encodingUnit["ObjectBlock"].printInformation()
