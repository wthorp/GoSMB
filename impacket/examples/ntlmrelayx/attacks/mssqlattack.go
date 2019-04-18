// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// MSSQL Attack Class
//
// Authors:
//  Alberto Solino (@agsolino)
//  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
//
// Description:
//  MSSQL protocol relay attack
//
// ToDo:
//
from impacket import LOG
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack

PROTOCOL_ATTACK_CLASS = "MSSQLAttack"

 type MSSQLAttack struct { // ProtocolAttack:
    PLUGIN_NAMES = ["MSSQL"]
     func (self TYPE) run(){
        if self.config.queries == nil {
            LOG.error("No SQL queries specified for MSSQL relay!")
        } else  {
            for query in self.config.queries:
                LOG.info('Executing SQL: %s' % query)
                self.client.sql_query(query)
                self.client.printReplies()
                self.client.printRows()
