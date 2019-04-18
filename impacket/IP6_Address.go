// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//

import array
from six import string_types

 type IP6_Address: struct {
    ADDRESS_BYTE_SIZE = 16
    //A Hex Group is a 16-bit unit of the address
    TOTAL_HEX_GROUPS = 8
    HEX_GROUP_SIZE = 4 //Size in characters
    TOTAL_SEPARATORS = TOTAL_HEX_GROUPS - 1
    ADDRESS_TEXT_SIZE = (TOTAL_HEX_GROUPS * HEX_GROUP_SIZE) + TOTAL_SEPARATORS
    SEPARATOR = ":"
    SCOPE_SEPARATOR = "%"
    
//############################################################################################################
// Constructor and construction helpers

     func (self TYPE) __init__(address interface{}){
        //The internal representation of an IP6 address is a 16-byte array
        self.__bytes = array.array('B', b'\0' * self.ADDRESS_BYTE_SIZE)
        self.__scope_id = ""

        //Invoke a constructor based on the type of the argument
        if isinstance(address, string_types) {
            self.__from_string(address)
        } else  {
            self.__from_bytes(address)


     func (self TYPE) __from_string(address interface{}){
        //Separate the Scope ID, if present
        if self.__is_a_scoped_address(address) {
            split_parts = address.split(self.SCOPE_SEPARATOR)
            address = split_parts[0]
            if split_parts[1] == "" {
                raise Exception("Empty scope ID")
            self.__scope_id = split_parts[1]
        
        //Expand address if it's in compressed form
        if self.__is_address_in_compressed_form(address) {
            address = self.__expand_compressed_address(address)
            
        //Insert leading zeroes where needed        
        address = self.__insert_leading_zeroes(address)
        
        //Sanity check
        if len(address) != self.ADDRESS_TEXT_SIZE {
            raise Exception('IP6_Address - from_string - address size != ' + str(self.ADDRESS_TEXT_SIZE))
    
        //Split address into hex groups
        hex_groups = address.split(self.SEPARATOR)
        if len(hex_groups) != self.TOTAL_HEX_GROUPS {
            raise Exception('IP6_Address - parsed hex groups != ' + str(self.TOTAL_HEX_GROUPS))

        //For each hex group, convert it into integer words
        offset = 0
        for group in hex_groups:
            if len(group) != self.HEX_GROUP_SIZE {
                raise Exception('IP6_Address - parsed hex group length != ' + str(self.HEX_GROUP_SIZE))
            
            group_as_int = int(group, 16)
            self.__bytes[offset]     = (group_as_int & 0xFF00) >> 8
            self.__bytes[offset + 1] = (group_as_int & 0x00FF) 
            offset += 2            

     func (self TYPE) __from_bytes(theBytes interface{}){
        if len(theBytes) != self.ADDRESS_BYTE_SIZE {
            raise Exception ("IP6_Address - from_bytes - array size != " + str(self.ADDRESS_BYTE_SIZE))
        self.__bytes = theBytes

//############################################################################################################
// Projectors
     func (self TYPE) as_string(compress_address = true, scoped_address = true interface{}){
        s = ""
        for i, v in enumerate(self.__bytes):
            s += hex(v)[2:].rjust(2, '0')
            if i % 2 == 1 {
                s += self.SEPARATOR
        s = s[:-1].upper()
        
        if compress_address {
            s = self.__trim_leading_zeroes(s)
            s = self.__trim_longest_zero_chain(s)
            
        if scoped_address and self.get_scope_id() != "" {
            s += self.SCOPE_SEPARATOR + self.__scope_id
        return s
                
     func (self TYPE) as_bytes(){
        return self.__bytes
    
     func (self TYPE) __str__(){
        return self.as_string()
    
     func (self TYPE) get_scope_id(){
        return self.__scope_id
    
     func (self TYPE) get_unscoped_address(){
        return self.as_string(true, false) //Compressed address = true, Scoped address = false
        
//############################################################################################################
// Semantic helpers
     func (self TYPE) is_multicast(){
        return self.__bytes[0] == 0xFF
    
     func (self TYPE) is_unicast(){
        return self.__bytes[0] == 0xFE
    
     func (self TYPE) is_link_local_unicast(){
        return self.is_unicast() and (self.__bytes[1] & 0xC0 == 0x80)
    
     func (self TYPE) is_site_local_unicast(){
        return self.is_unicast() and (self.__bytes[1] & 0xC0 == 0xC0)
    
     func (self TYPE) is_unique_local_unicast(){
        return self.__bytes[0] == 0xFD
                
    
     func (self TYPE) get_human_readable_address_type(){
        if self.is_multicast() {
            return "multicast"
        elif self.is_unicast() {
            if self.is_link_local_unicast() {
                return "link-local unicast"
            elif self.is_site_local_unicast() {
                return "site-local unicast"
            } else  {
                return "unicast"
        elif self.is_unique_local_unicast() {
            return "unique-local unicast"
        } else  {
            return "unknown type"

//############################################################################################################
//Expansion helpers

    //Predicate - returns whether an address is in compressed form
     func (self TYPE) __is_address_in_compressed_form(address interface{}){
        //Sanity check - triple colon detection (not detected by searches of double colon)        
        if address.count(self.SEPARATOR * 3) > 0 {
            raise Exception("IP6_Address - found triple colon")
        
        //Count the double colon marker
        compression_marker_count = self.__count_compression_marker(address)        
        if compression_marker_count == 0 {
            return false
        elif compression_marker_count == 1 {
            return true
        } else  {
            raise Exception("IP6_Address - more than one compression marker (\"::\") found")
       
    //Returns how many hex groups are present, in a compressed address 
     func (self TYPE) __count_compressed_groups(address interface{}){
        trimmed_address = address.replace(self.SEPARATOR * 2, self.SEPARATOR) //Replace "::" with ":"        
        return trimmed_address.count(self.SEPARATOR) + 1

    //Counts how many compression markers are present
     func (self TYPE) __count_compression_marker(address interface{}){
        return address.count(self.SEPARATOR * 2) //Count occurrences of "::"

    //Inserts leading zeroes in every hex group
     func (self TYPE) __insert_leading_zeroes(address interface{}){
        hex_groups = address.split(self.SEPARATOR)
        
        new_address = ""
        for hex_group in hex_groups:
            if len(hex_group) < 4 {
                hex_group = hex_group.rjust(4, "0")
            new_address += hex_group + self.SEPARATOR
            
        return new_address[:-1] //Trim the last colon
            
            
    //Expands a compressed address
     func (self TYPE) __expand_compressed_address(address interface{}){
        group_count = self.__count_compressed_groups(address)
        groups_to_insert = self.TOTAL_HEX_GROUPS - group_count
        
        pos = address.find(self.SEPARATOR * 2) + 1 
        while groups_to_insert:
            address = address[:pos] + "0000" + self.SEPARATOR + address[pos:]
            pos += 5
            groups_to_insert -= 1

        //Replace the compression marker with a single colon            
        address = address.replace(self.SEPARATOR * 2, self.SEPARATOR)        
        return address


//############################################################################################################
//Compression helpers

     func (self TYPE) __trim_longest_zero_chain(address interface{}){
        chain_size = 8
        
        while chain_size > 0:
            groups = address.split(self.SEPARATOR)

            for index, group in enumerate(groups):
                //Find the first zero
                if group == "0" {
                    start_index = index
                    end_index = index
                    //Find the end of this chain of zeroes
                    while end_index < 7 and groups[end_index + 1] == "0":
                        end_index += 1
                        
                    //If the zero chain matches the current size, trim it
                    found_size = end_index - start_index + 1
                    if found_size == chain_size {
                        address = self.SEPARATOR.join(groups[0:start_index]) + self.SEPARATOR * 2 + self.SEPARATOR.join(groups[(end_index+1):])
                        return address
                    
            //No chain of this size found, try with a lower size    
            chain_size -= 1
        return address

                                
    //Trims all leading zeroes from every hex group
     func (self TYPE) __trim_leading_zeroes(theStr interface{}){
        groups = theStr.split(self.SEPARATOR)
        theStr = ""
        
        for group in groups:
            group = group.lstrip("0") + self.SEPARATOR
            if group == self.SEPARATOR {
                group = "0" + self.SEPARATOR
            theStr += group
        return theStr[:-1]
                

//############################################################################################################
    @classmethod
     func is_a_valid_text_representation(cls, text_representation interface{}){
        try:
            //Capitalize on the constructor's ability to detect invalid text representations of an IP6 address            
            IP6_Address(text_representation)
            return true
        except Exception:
            return false
                
     func (self TYPE) __is_a_scoped_address(text_representation interface{}){
        return text_representation.count(self.SCOPE_SEPARATOR) == 1
