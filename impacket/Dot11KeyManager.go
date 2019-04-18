// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Description:
//  IEEE 802.11 Network packet codecs.
//
// Author:
//  Gustavo Moreira

from array import array
 type KeyManager: struct {
     func (self TYPE) __init__(){
        self.keys = {}
        
     func (self TYPE) __get_bssid_hasheable_type(bssid interface{}){
        // List is an unhashable type
        if not isinstance(bssid, (list,tuple,array)) {
            raise Exception("BSSID datatype must be a tuple, list or array")
        return tuple(bssid) 

     func (self TYPE) add_key(bssid, key interface{}){
        bssid=self.__get_bssid_hasheable_type(bssid)
        if bssid not in self.keys {
            self.keys[bssid] = key
            return true
        } else  {
            return false
        
     func (self TYPE) replace_key(bssid, key interface{}){
        bssid=self.__get_bssid_hasheable_type(bssid)
        self.keys[bssid] = key
        
        return true
        
     func (self TYPE) get_key(bssid interface{}){
        bssid=self.__get_bssid_hasheable_type(bssid)
        if bssid in self.keys {
            return self.keys[bssid]
        } else  {
            return false
        
     func (self TYPE) delete_key(bssid interface{}){
        bssid=self.__get_bssid_hasheable_type(bssid)
        if not isinstance(bssid, list) {
            raise Exception("BSSID datatype must be a list")
        
        if bssid in self.keys {
            del self.keys[bssid] 
            return true
        
        return false
