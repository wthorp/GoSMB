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
//
// Altered source by Alberto Solino (@agsolino)
//
// Changed some of the classes names to match the RFC 4120
// Added [MS-KILE] data
// Adapted to Enum
//


from pyasn1.type import tag, namedtype, univ, constraint, char, useful

from . import constants


 func _application_tag(tag_value interface{}){
    return univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed,
                int(tag_value)))

 func _vno_component(tag_value, name="pvno" interface{}){
    return _sequence_component(
        name, tag_value, univ.Integer(),
        subtypeSpec=constraint.ValueRangeConstraint(5, 5))

 func _msg_type_component(tag_value, values interface{}){
    c = constraint.ConstraintsUnion(
        *(constraint.SingleValueConstraint(int(v)) for v in values))
    return _sequence_component('msg-type', tag_value, univ.Integer(),
                               subtypeSpec=c)

 func _sequence_component(name, tag_value, type, **subkwargs interface{}){
    return namedtype.NamedType(name, type.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple,
                            tag_value),
        **subkwargs))

 func _sequence_optional_component(name, tag_value, type, **subkwargs interface{}){
    return namedtype.OptionalNamedType(name, type.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple,
                            tag_value),
        **subkwargs))

 func seq_set(seq, name, builder=nil, *args, **kwargs interface{}){
    component = seq.setComponentByName(name).getComponentByName(name)
    if builder is not nil {
        seq.setComponentByName(name, builder(component, *args, **kwargs))
    } else  {
        seq.setComponentByName(name)
    return seq.getComponentByName(name)

 func seq_set_dict(seq, name, pairs, *args, **kwargs interface{}){
    component = seq.setComponentByName(name).getComponentByName(name)
    for k, v in pairs.items():
        component.setComponentByName(k, v)

 func seq_set_iter(seq, name, iterable interface{}){
    component = seq.setComponentByName(name).getComponentByName(name)
    for pos, v in enumerate(iterable):
        component.setComponentByPosition(pos, v)

 func seq_set_flags(seq, name, flags interface{}){
    seq_set(seq, name, flags.to_asn1)

 func seq_append(seq, name, pairs interface{}){
    component = seq.getComponentByName(name)
    if component == nil {
        component = seq.setComponentByName(name).getComponentByName(name)
    index = len(component)
    element = component.setComponentByPosition(index
                                               }.getComponentByPosition(index)
    for k, v in pairs.items():
        element.setComponentByName(k, v)

 type Int32 struct { // univ.Integer:
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        -2147483648, 2147483647)

 type UInt32 struct { // univ.Integer:
    pass
//    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
//        0, 4294967295)

 type Microseconds struct { // univ.Integer:
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        0, 999999)

 type KerberosString struct { // char.GeneralString:
    // TODO marc: I'm not sure how to express this constraint in the API.
    // For now, we will be liberal in what we accept.
    // subtypeSpec = constraint.PermittedAlphabetConstraint(char.IA5String())
    pass

 type Realm struct { // KerberosString:
    pass

 type PrincipalName struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component("name-type", 0, Int32()),
        _sequence_component("name-string", 1,
                            univ.SequenceOf(componentType=KerberosString()))
                            }

 type KerberosTime struct { // useful.GeneralizedTime:
    pass

 type HostAddress struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component("addr-type", 0, Int32()),
        _sequence_component("address", 1, univ.OctetString())
        }

 type HostAddresses struct { // univ.SequenceOf:
    componentType = HostAddress()

 type AuthorizationData struct { // univ.SequenceOf:
    componentType = univ.Sequence(componentType=namedtype.NamedTypes(
        _sequence_component('ad-type', 0, Int32()),
        _sequence_component('ad-data', 1, univ.OctetString())
        })

 type PA_DATA struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('padata-type', 1, Int32()),
        _sequence_component('padata-value', 2, univ.OctetString())
        }

 type KerberosFlags struct { // univ.BitString:
    // TODO marc: it doesn't look like there's any way to specify the
    // SIZE (32.. MAX) parameter to the encoder.  However, we can
    // arrange at a higher layer to pass in >= 32 bits to the encoder.
    pass

 type EncryptedData struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component("etype", 0, Int32()),
        _sequence_optional_component("kvno", 1, UInt32()),
        _sequence_component("cipher", 2, univ.OctetString())
        }

 type EncryptionKey struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('keytype', 0, Int32()),
        _sequence_component('keyvalue', 1, univ.OctetString()))

 type Checksum struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('cksumtype', 0, Int32()),
        _sequence_component('checksum', 1, univ.OctetString()))

 type Ticket struct { // univ.Sequence:
    tagSet = _application_tag(constants.ApplicationTagNumbers.Ticket.value)
    componentType = namedtype.NamedTypes(
        _vno_component(name="tkt-vno", tag_value=0),
        _sequence_component("realm", 1, Realm()),
        _sequence_component("sname", 2, PrincipalName()),
        _sequence_component("enc-part", 3, EncryptedData())
        }

 type TicketFlags struct { // KerberosFlags:
    pass

 type TransitedEncoding struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('tr-type', 0, Int32()),
        _sequence_component('contents', 1, univ.OctetString()))

 type EncTicketPart struct { // univ.Sequence:
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncTicketPart.value)
    componentType = namedtype.NamedTypes(
        _sequence_component("flags", 0, TicketFlags()),
        _sequence_component("key", 1, EncryptionKey()),
        _sequence_component("crealm", 2, Realm()),
        _sequence_component("cname", 3, PrincipalName()),
        _sequence_component("transited", 4, TransitedEncoding()),
        _sequence_component("authtime", 5, KerberosTime()),
        _sequence_optional_component("starttime", 6, KerberosTime()),
        _sequence_component("endtime", 7, KerberosTime()),
        _sequence_optional_component("renew-till", 8, KerberosTime()),
        _sequence_optional_component("caddr", 9, HostAddresses()),
        _sequence_optional_component("authorization-data", 10, AuthorizationData())
        }

 type KDCOptions struct { // KerberosFlags:
    pass

 type KDC_REQ_BODY struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('kdc-options', 0, KDCOptions()),
        _sequence_optional_component('cname', 1, PrincipalName()),
        _sequence_component('realm', 2, Realm()),
        _sequence_optional_component('sname', 3, PrincipalName()),
        _sequence_optional_component('from', 4, KerberosTime()),
        _sequence_component('till', 5, KerberosTime()),
        _sequence_optional_component('rtime', 6, KerberosTime()),
        _sequence_component('nonce', 7, UInt32()),
        _sequence_component('etype', 8,
                            univ.SequenceOf(componentType=Int32())),
        _sequence_optional_component('addresses', 9, HostAddresses()),
        _sequence_optional_component('enc-authorization-data', 10,
                                     EncryptedData()),
        _sequence_optional_component('additional-tickets', 11,
                                     univ.SequenceOf(componentType=Ticket()))
        }

 type KDC_REQ struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _vno_component(1),
        _msg_type_component(2, (constants.ApplicationTagNumbers.AS_REQ.value,
                                constants.ApplicationTagNumbers.TGS_REQ.value)),
        _sequence_optional_component('padata', 3,
                                     univ.SequenceOf(componentType=PA_DATA())),
        _sequence_component('req-body', 4, KDC_REQ_BODY())
        }

 type AS_REQ struct { // KDC_REQ:
    tagSet = _application_tag(constants.ApplicationTagNumbers.AS_REQ.value)

 type TGS_REQ struct { // KDC_REQ:
    tagSet = _application_tag(constants.ApplicationTagNumbers.TGS_REQ.value)

 type KDC_REP struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.AS_REP.value,
                                constants.ApplicationTagNumbers.TGS_REP.value)),
        _sequence_optional_component('padata', 2,
                                     univ.SequenceOf(componentType=PA_DATA())),
        _sequence_component('crealm', 3, Realm()),
        _sequence_component('cname', 4, PrincipalName()),
        _sequence_component('ticket', 5, Ticket()),
        _sequence_component('enc-part', 6, EncryptedData())
        }

 type LastReq struct { // univ.SequenceOf:
    componentType = univ.Sequence(componentType=namedtype.NamedTypes(
        _sequence_component('lr-type', 0, Int32()),
        _sequence_component('lr-value', 1, KerberosTime())
        })

 type METHOD_DATA struct { // univ.SequenceOf:
    componentType = PA_DATA()

 type EncKDCRepPart struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('key', 0, EncryptionKey()),
        _sequence_component('last-req', 1, LastReq()),
        _sequence_component('nonce', 2, UInt32()),
        _sequence_optional_component('key-expiration', 3, KerberosTime()),
        _sequence_component('flags', 4, TicketFlags()),
        _sequence_component('authtime', 5, KerberosTime()),
        _sequence_optional_component('starttime', 6, KerberosTime()),
        _sequence_component('endtime', 7, KerberosTime()),
        _sequence_optional_component('renew-till', 8, KerberosTime()),
        _sequence_component('srealm', 9, Realm()),
        _sequence_component('sname', 10, PrincipalName()),
        _sequence_optional_component('caddr', 11, HostAddresses()),
        _sequence_optional_component('encrypted_pa_data', 12, METHOD_DATA())
        }

 type EncASRepPart struct { // EncKDCRepPart:
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncASRepPart.value)

 type EncTGSRepPart struct { // EncKDCRepPart:
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncTGSRepPart.value)

 type AS_REP struct { // KDC_REP:
    tagSet = _application_tag(constants.ApplicationTagNumbers.AS_REP.value)

 type TGS_REP struct { // KDC_REP:
    tagSet = _application_tag(constants.ApplicationTagNumbers.TGS_REP.value)

 type APOptions struct { // KerberosFlags:
    pass

 type Authenticator struct { // univ.Sequence:
    tagSet = _application_tag(constants.ApplicationTagNumbers.Authenticator.value)
    componentType = namedtype.NamedTypes(
        _vno_component(name='authenticator-vno', tag_value=0),
        _sequence_component('crealm', 1, Realm()),
        _sequence_component('cname', 2, PrincipalName()),
        _sequence_optional_component('cksum', 3, Checksum()),
        _sequence_component('cusec', 4, Microseconds()),
        _sequence_component('ctime', 5, KerberosTime()),
        _sequence_optional_component('subkey', 6, EncryptionKey()),
        _sequence_optional_component('seq-number', 7, UInt32()),
        _sequence_optional_component('authorization-data', 8,
                                     AuthorizationData())
        }

 type AP_REQ struct { // univ.Sequence:
    tagSet = _application_tag(constants.ApplicationTagNumbers.AP_REQ.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.AP_REQ.value,)),
        _sequence_component('ap-options', 2, APOptions()),
        _sequence_component('ticket', 3, Ticket()),
        _sequence_component('authenticator', 4, EncryptedData())
        }

 type AP_REP struct { // univ.Sequence:
    tagSet = _application_tag(constants.ApplicationTagNumbers.AP_REP.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.AP_REP.value,)),
        _sequence_component('enc-part', 2, EncryptedData()),
        }

 type EncAPRepPart struct { // univ.Sequence:
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncApRepPart.value)
    componentType = namedtype.NamedTypes(
        _sequence_component('ctime', 0, KerberosTime()),
        _sequence_component('cusec', 1, Microseconds()),
        _sequence_optional_component('subkey', 2, EncryptionKey()),
        _sequence_optional_component('seq-number', 3, UInt32()),
        }

 type KRB_SAFE_BODY struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('user-data', 0, univ.OctetString()),
        _sequence_optional_component('timestamp', 1, KerberosTime()),
        _sequence_optional_component('usec', 2, Microseconds()),
        _sequence_optional_component('seq-number', 3, UInt32()),
        _sequence_component('s-address', 4, HostAddress()),
        _sequence_optional_component('r-address', 5, HostAddress()),
        }

 type KRB_SAFE struct { // univ.Sequence:
    tagSet = _application_tag(constants.ApplicationTagNumbers.KRB_SAFE.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.KRB_SAFE.value,)),
        _sequence_component('safe-body', 2, KRB_SAFE_BODY()),
        _sequence_component('cksum', 3, Checksum()),
        }

 type KRB_PRIV struct { // univ.Sequence:
    tagSet = _application_tag(constants.ApplicationTagNumbers.KRB_PRIV.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.KRB_PRIV.value,)),
        _sequence_component('enc-part', 3, EncryptedData()),
        }

 type EncKrbPrivPart struct { // univ.Sequence:
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncKrbPrivPart.value)
    componentType = namedtype.NamedTypes(
        _sequence_component('user-data', 0, univ.OctetString()),
        _sequence_optional_component('timestamp', 1, KerberosTime()),
        _sequence_optional_component('cusec', 2, Microseconds()),
        _sequence_optional_component('seq-number', 3, UInt32()),
        _sequence_component('s-address', 4, HostAddress()),
        _sequence_optional_component('r-address', 5, HostAddress()),
        }

 type KRB_CRED struct { // univ.Sequence:
    tagSet = _application_tag(constants.ApplicationTagNumbers.KRB_CRED.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.KRB_CRED.value,)),
        _sequence_optional_component('tickets', 2,
                                     univ.SequenceOf(componentType=Ticket())),
        _sequence_component('enc-part', 3, EncryptedData()),
        }

 type KrbCredInfo struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('key', 0, EncryptionKey()),
        _sequence_optional_component('prealm', 1, Realm()),
        _sequence_optional_component('pname', 2, PrincipalName()),
        _sequence_optional_component('flags', 3, TicketFlags()),
        _sequence_optional_component('authtime', 4, KerberosTime()),
        _sequence_optional_component('starttime', 5, KerberosTime()),
        _sequence_optional_component('endtime', 6, KerberosTime()),
        _sequence_optional_component('renew-till', 7, KerberosTime()),
        _sequence_optional_component('srealm', 8, Realm()),
        _sequence_optional_component('sname', 9, PrincipalName()),
        _sequence_optional_component('caddr', 10, HostAddresses()),
        }

 type EncKrbCredPart struct { // univ.Sequence:
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncKrbCredPart.value)
    componentType = namedtype.NamedTypes(
        _sequence_component('ticket-info', 0, univ.SequenceOf(componentType=KrbCredInfo())),
        _sequence_optional_component('nonce', 1, UInt32()),
        _sequence_optional_component('timestamp', 2, KerberosTime()),
        _sequence_optional_component('usec', 3, Microseconds()),
        _sequence_optional_component('s-address', 4, HostAddress()),
        _sequence_optional_component('r-address', 5, HostAddress()),
        }

 type KRB_ERROR struct { // univ.Sequence:
    tagSet = _application_tag(constants.ApplicationTagNumbers.KRB_ERROR.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.KRB_ERROR.value,)),
        _sequence_optional_component('ctime', 2, KerberosTime()),
        _sequence_optional_component('cusec', 3, Microseconds()),
        _sequence_component('stime', 4, KerberosTime()),
        _sequence_component('susec', 5, Microseconds()),
        _sequence_component('error-code', 6, Int32()),
        _sequence_optional_component('crealm', 7, Realm()),
        _sequence_optional_component('cname', 8, PrincipalName()),
        _sequence_component('realm', 9, Realm()),
        _sequence_component('sname', 10, PrincipalName()),
        _sequence_optional_component('e-text', 11, KerberosString()),
        _sequence_optional_component('e-data', 12, univ.OctetString())
        }

 type TYPED_DATA struct { // univ.SequenceOf:
    componentType = namedtype.NamedTypes(
        _sequence_component('data-type', 0, Int32()),
        _sequence_optional_component('data-value', 1, univ.OctetString()),
    }

 type PA_ENC_TIMESTAMP struct { // EncryptedData:
    pass

 type PA_ENC_TS_ENC struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('patimestamp', 0, KerberosTime()),
        _sequence_optional_component('pausec', 1, Microseconds()))

 type ETYPE_INFO_ENTRY struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('etype', 0, Int32()),
        _sequence_optional_component('salt', 1, univ.OctetString()))

 type ETYPE_INFO struct { // univ.SequenceOf:
    componentType = ETYPE_INFO_ENTRY()

 type ETYPE_INFO2_ENTRY struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('etype', 0, Int32()),
        _sequence_optional_component('salt', 1, KerberosString()),
        _sequence_optional_component('s2kparams', 2, univ.OctetString()))

 type ETYPE_INFO2 struct { // univ.SequenceOf:
    componentType = ETYPE_INFO2_ENTRY()

 type AD_IF_RELEVANT struct { // AuthorizationData:
    pass

 type AD_KDCIssued struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('ad-checksum', 0, Checksum()),
        _sequence_optional_component('i-realm', 1, Realm()),
        _sequence_optional_component('i-sname', 2, PrincipalName()),
        _sequence_component('elements', 3, AuthorizationData()))

 type AD_AND_OR struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('condition-count', 0, Int32()),
        _sequence_optional_component('elements', 1, AuthorizationData()))

 type AD_MANDATORY_FOR_KDC struct { // AuthorizationData:
    pass

 type KERB_PA_PAC_REQUEST struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
    namedtype.NamedType('include-pac', univ.Boolean().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    }

 type PA_FOR_USER_ENC struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('userName', 0, PrincipalName()),
        _sequence_optional_component('userRealm', 1, Realm()),
        _sequence_optional_component('cksum', 2, Checksum()),
        _sequence_optional_component('auth-package', 3, KerberosString()))

 type KERB_ERROR_DATA struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('data-type', 1, Int32()),
        _sequence_component('data-value', 2, univ.OctetString()))

 type PA_PAC_OPTIONS struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        _sequence_component('flags', 0, KerberosFlags()),
    }

