// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Authors: Alberto Solino (@agsolino)
//          Kacper Nowak (@kacpern)
//
// Description:
//   RFC 4511 Minimalistic implementation. We don't need much functionality yet
//   If we need more complex use cases we might opt to use a third party implementation
//   Keep in mind the APIs are still unstable, might require to re-write your scripts
//   as we change them.
//   Adding [MS-ADTS] specific functionality
//

from pyasn1.codec.ber import encoder, decoder
from pyasn1.type import univ, namedtype, namedval, tag, constraint

__all__ = [
    'CONTROL_PAGEDRESULTS', 'CONTROL_SDFLAGS', 'KNOWN_CONTROLS', 'NOTIFICATION_DISCONNECT', 'KNOWN_NOTIFICATIONS',
    // classes
    'ResultCode', 'Scope', 'DerefAliases', 'Operation', 'MessageID', 'LDAPString', 'LDAPOID', 'LDAPDN',
    'RelativeLDAPDN', 'AttributeDescription', 'AttributeValue', 'AssertionValue', 'MatchingRuleID', 'URI',
    'AttributeValueAssertion', 'PartialAttribute', 'PartialAttributeList', 'Attribute', 'AttributeList',
    'AttributeSelection', 'Referral', 'LDAPResult', 'SaslCredentials', 'AuthenticationChoice', 'BindRequest',
    'BindResponse', 'UnbindRequest', 'SubstringFilter', 'MatchingRuleAssertion', 'Filter', 'SearchRequest',
    'SearchResultEntry', 'SearchResultReference', 'SearchResultDone', 'ModifyRequest', 'ModifyResponse', 'AddRequest',
    'AddResponse', 'DelRequest', 'DelResponse', 'ModifyDNRequest', 'ModifyDNResponse', 'CompareRequest',
    'CompareResponse', 'AbandonRequest', 'ExtendedRequest', 'ExtendedResponse', 'IntermediateResponse', 'Control',
    'Controls', 'SimplePagedResultsControlValue', 'SimplePagedResultsControl', 'LDAPMessage'
]

// Controls
CONTROL_PAGEDRESULTS = "1.2.840.113556.1.4.319"
CONTROL_SDFLAGS = "1.2.840.113556.1.4.801"

KNOWN_CONTROLS = {}

// Unsolicited notifications
NOTIFICATION_DISCONNECT = "1.3.6.1.4.1.1466.20036"

KNOWN_NOTIFICATIONS = {NOTIFICATION_DISCONNECT: 'Notice of Disconnection'}

maxInt = univ.Integer(2147483647)


 type DefaultSequenceAndSetBaseMixin: struct {
     func (self TYPE) getComponentByPosition(idx, default=univ.noValue, instantiate=true interface{}){
        for cls in self.__class__.__bases__:
            if cls is not DefaultSequenceAndSetBaseMixin {
                try:
                    component = cls.getComponentByPosition(self, idx)//, default, instantiate)
                except AttributeError:
                    continue
                if component == nil {
                    return self.setComponentByPosition(idx).getComponentByPosition(idx)// , default, instantiate)
                return component


 type ResultCode struct { // univ.Enumerated:
    namedValues = namedval.NamedValues(
        ('success', 0),
        ('operationsError', 1),
        ('protocolError', 2),
        ('timeLimitExceeded', 3),
        ('sizeLimitExceeded', 4),
        ('comparefalse', 5),
        ('comparetrue', 6),
        ('authMethodNotSupported', 7),
        ('strongerAuthRequired', 8),
        ('referral', 10),
        ('adminLimitExceeded', 11),
        ('unavailableCriticalExtension', 12),
        ('confidentialityRequired', 13),
        ('saslBindInProgress', 14),
        ('noSuchAttribute', 16),
        ('undefinedAttributeType', 17),
        ('inappropriateMatching', 18),
        ('constraintViolation', 19),
        ('attributeOrValueExists', 20),
        ('invalidAttributeSyntax', 21),
        ('noSuchObject', 32),
        ('aliasProblem', 33),
        ('invalidDNSyntax', 34),
        ('aliasDereferencingProblem', 36),
        ('inappropriateAuthentication', 48),
        ('invalidCredentials', 49),
        ('insufficientAccessRights', 50),
        ('busy', 51),
        ('unavailable', 52),
        ('unwillingToPerform', 53),
        ('loopDetect', 54),
        ('namingViolation', 64),
        ('objectClassViolation', 65),
        ('notAllowedOnNonLeaf', 66),
        ('notAllowedOnRDN', 67),
        ('entryAlreadyExists', 68),
        ('objectClassModsProhibited', 69),
        ('affectsMultipleDSAs', 71),
        ('other', 80),
    }


 type Scope struct { // univ.Enumerated:
    namedValues = namedval.NamedValues(
        ('baseObject', 0),
        ('singleLevel', 1),
        ('wholeSubtree', 2),
    }


 type DerefAliases struct { // univ.Enumerated:
    namedValues = namedval.NamedValues(
        ('neverDerefAliases', 0),
        ('derefInSearching', 1),
        ('derefFindingBaseObj', 2),
        ('derefAlways', 3),
    }


 type Operation struct { // univ.Enumerated:
    namedValues = namedval.NamedValues(
        ('add', 0),
        ('delete', 1),
        ('replace', 2),
    }


 type MessageID struct { // univ.Integer:
    subtypeSpec = constraint.ValueRangeConstraint(0, maxInt)


 type LDAPString struct { // univ.OctetString:
    encoding = "utf-8"


 type LDAPOID struct { // univ.OctetString:
    pass


 type LDAPDN struct { // LDAPString:
    pass


 type RelativeLDAPDN struct { // LDAPString:
    pass


 type AttributeDescription struct { // LDAPString:
    pass


 type AttributeValue struct { // univ.OctetString:
    pass


 type AssertionValue struct { // univ.OctetString:
    pass


 type MatchingRuleID struct { // LDAPString:
    pass


 type URI struct { // LDAPString:
    pass


 type AttributeValueAssertion struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attributeDesc', AttributeDescription()),
        namedtype.NamedType('assertionValue', AssertionValue())
    }


 type PartialAttribute struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeDescription()),
        namedtype.NamedType('vals', univ.SetOf(componentType=AttributeValue()))
    }


 type PartialAttributeList struct { // univ.SequenceOf:
    componentType = PartialAttribute()


 type Attribute struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeDescription()),
        namedtype.NamedType(
            'vals',
            univ.SetOf(componentType=AttributeValue()).subtype(subtypeSpec=constraint.ValueSizeConstraint(1, maxInt))
        }
    }


 type AttributeList struct { // univ.SequenceOf:
    componentType = Attribute()


 type AttributeSelection struct { // univ.SequenceOf:
    componentType = LDAPString()


 type Referral struct { // univ.SequenceOf:
    componentType = URI()
    subtypeSpec = constraint.ValueSizeConstraint(1, maxInt)


 type LDAPResult struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('resultCode', ResultCode()),
        namedtype.NamedType('matchedDN', LDAPDN()),
        namedtype.NamedType('diagnosticMessage', LDAPString()),
        namedtype.OptionalNamedType(
            'referral', Referral().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
        }
    }


 type SaslCredentials struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('mechanism', LDAPString()),
        namedtype.OptionalNamedType('credentials', univ.OctetString())
    }


 type AuthenticationChoice struct { // DefaultSequenceAndSetBaseMixin, univ.Choice:
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'simple',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        },
        namedtype.NamedType(
            'sasl',
            SaslCredentials().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
        },
        namedtype.NamedType(
            'sicilyPackageDiscovery',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))
        },
        namedtype.NamedType(
            'sicilyNegotiate',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))
        },
        namedtype.NamedType(
            'sicilyResponse',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11))
        }
    }


 type BindRequest struct { // DefaultSequenceAndSetBaseMixin, univ.Sequence:
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(1, 127))),
        namedtype.NamedType('name', LDAPDN()),
        namedtype.NamedType('authentication', AuthenticationChoice())
    }


 type BindResponse struct { // univ.Sequence:
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('resultCode', ResultCode()),
        namedtype.NamedType('matchedDN', LDAPDN()),
        namedtype.NamedType('diagnosticMessage', LDAPString()),
        namedtype.OptionalNamedType(
            'referral',
            Referral().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
        },
        namedtype.OptionalNamedType(
            'serverSaslCreds',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))
        }
    }


 type UnbindRequest struct { // univ.Null:
    tagSet = univ.Null.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 2))


 type SubstringFilter struct { // DefaultSequenceAndSetBaseMixin, univ.Sequence:
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeDescription()),
        namedtype.NamedType(
            'substrings',
            univ.SequenceOf(componentType=univ.Choice(componentType=namedtype.NamedTypes(
                namedtype.NamedType(
                    'initial',
                    AssertionValue().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
                },
                namedtype.NamedType(
                    'any',
                    AssertionValue().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
                },
                namedtype.NamedType(
                    'final',
                    AssertionValue().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
                }
            }))
        }
    }


 type MatchingRuleAssertion struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'matchingRule',
            MatchingRuleID().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        },
        namedtype.OptionalNamedType(
            'type',
            AttributeDescription().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
        },
        namedtype.NamedType(
            'matchValue',
            AssertionValue().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
        },
        namedtype.DefaultedNamedType(
            'dnAttributes',
            univ.Boolean().subtype(value=false, implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))
        }
    }


 type Filter struct { // DefaultSequenceAndSetBaseMixin, univ.Choice:
    pass


Filter.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        'and',
        univ.SetOf(componentType=Filter()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    },
    namedtype.NamedType(
        'or',
        univ.SetOf(componentType=Filter()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
    },
    namedtype.NamedType(
        'not',
        univ.SetOf(componentType=Filter()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
        //Filter().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
    },
    namedtype.NamedType(
        'equalityMatch',
        AttributeValueAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
    },
    namedtype.NamedType(
        'substrings',
        SubstringFilter().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))
    },
    namedtype.NamedType(
        'greaterOrEqual',
        AttributeValueAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5))
    },
    namedtype.NamedType(
        'lessOrEqual',
        AttributeValueAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6))
    },
    namedtype.NamedType(
        'present',
        AttributeDescription().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))
    },
    namedtype.NamedType(
        'approxMatch',
        AttributeValueAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8))
    },
    namedtype.NamedType(
        'extensibleMatch',
        MatchingRuleAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 9))
    }
}


 type SearchRequest struct { // DefaultSequenceAndSetBaseMixin, univ.Sequence:
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 3))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('baseObject', LDAPDN()),
        namedtype.NamedType('scope', Scope()),
        namedtype.NamedType('derefAliases', DerefAliases()),
        namedtype.NamedType(
            'sizeLimit', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, maxInt))
        },
        namedtype.NamedType(
            'timeLimit', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, maxInt))
        },
        namedtype.NamedType('typesOnly', univ.Boolean()),
        namedtype.NamedType('filter', Filter()),
        namedtype.NamedType('attributes', AttributeSelection())
    }


 type SearchResultEntry struct { // univ.Sequence:
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 4))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('objectName', LDAPDN()),
        namedtype.NamedType('attributes', PartialAttributeList())
    }


 type SearchResultReference struct { // univ.SequenceOf:
    tagSet = univ.SequenceOf.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 19))
    componentType = URI()
    subtypeSpec = constraint.ValueSizeConstraint(1, maxInt)


 type SearchResultDone struct { // LDAPResult:
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 5))


 type ModifyRequest struct { // DefaultSequenceAndSetBaseMixin, univ.Sequence:
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 6))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('object', LDAPDN()),
        namedtype.NamedType(
            'changes',
            univ.SequenceOf(componentType=univ.Sequence(componentType=namedtype.NamedTypes(
                namedtype.NamedType('operation', Operation()),
                namedtype.NamedType('modification', PartialAttribute())
            }))
        }
    }


 type ModifyResponse struct { // LDAPResult:
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 7))


 type AddRequest struct { // DefaultSequenceAndSetBaseMixin, univ.Sequence:
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 8))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('entry', LDAPDN()),
        namedtype.NamedType('attributes', AttributeList())
    }


 type AddResponse struct { // LDAPResult:
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 9))


 type DelRequest struct { // LDAPDN:
    tagSet = LDAPDN.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 10))


 type DelResponse struct { // LDAPResult:
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 11))


 type ModifyDNRequest struct { // univ.Sequence:
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 12))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('entry', LDAPDN()),
        namedtype.NamedType('newrdn', RelativeLDAPDN()),
        namedtype.NamedType('deleteoldrdn', univ.Boolean()),
        namedtype.OptionalNamedType(
            'newSuperior', LDAPDN().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        }
    }


 type ModifyDNResponse struct { // LDAPResult:
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 13))


 type CompareRequest struct { // DefaultSequenceAndSetBaseMixin, univ.Sequence:
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 14))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('entry', LDAPDN()),
        namedtype.NamedType('ava', AttributeValueAssertion())
    }


 type CompareResponse struct { // LDAPResult:
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 15))


 type AbandonRequest struct { // MessageID:
    tagSet = MessageID.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 16))


 type ExtendedRequest struct { // univ.Sequence:
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 23))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'requestName', LDAPOID().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        },
        namedtype.OptionalNamedType(
            'requestValue', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        }
    }


 type ExtendedResponse struct { // univ.Sequence:
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 24))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('resultCode', ResultCode()),
        namedtype.NamedType('matchedDN', LDAPDN()),
        namedtype.NamedType('diagnosticMessage', LDAPString()),
        namedtype.OptionalNamedType(
            'referral',
            Referral().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
        },
        namedtype.OptionalNamedType(
            'responseName',
            LDAPOID().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))
        },
        namedtype.OptionalNamedType(
            'responseValue',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11))
        }
    }


 type IntermediateResponse struct { // univ.Sequence:
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 25))
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'responseName',
            LDAPOID().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        },
        namedtype.OptionalNamedType(
            'responseValue',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        }
    }


 type Control struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('controlType', LDAPOID()),
        namedtype.DefaultedNamedType('criticality', univ.Boolean().subtype(value=false)),
        namedtype.OptionalNamedType('controlValue', univ.OctetString())
    }

    def setComponentByPosition(self, idx, value=univ.noValue,
                               verifyConstraints=true,
                               matchTags=true,
                               matchConstraints=true):
        if idx == 0 {  // controlType
            try:
                cls = KNOWN_CONTROLS[value]
                if self.__class__ is not cls {
                    self.__class__ = cls
            except KeyError:
                pass
        return univ.Sequence.setComponentByPosition(self, idx, value=value,
                                                    verifyConstraints=verifyConstraints,
                                                    matchTags=matchTags,
                                                    matchConstraints=matchConstraints)

     func (self TYPE) encodeControlValue(){
        pass

     func (self TYPE) decodeControlValue(){
        return

     func (self TYPE) prettyPrint(scope=0 interface{}){
        r = univ.Sequence.prettyPrint(self, scope)
        decodedControlValue = self.decodeControlValue()
        if decodedControlValue is not nil {
            r = r[:r.rindex("=") + 1] + '%s\n' % decodedControlValue.prettyPrint(scope + 1)
        return r


 type Controls struct { // univ.SequenceOf:
    componentType = Control()


 type SDFlagsControlValue struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('flags', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, maxInt))),
    }

 type SDFlagsControl struct { // Control:
     func (self TYPE) __init__(criticality=nil, flags=0x00000007, **kwargs interface{}){
        Control.__init__(self, **kwargs)
        self.controlType = CONTROL_SDFLAGS
        if criticality is not nil {
            self.criticality = criticality
        self.flags = flags
        self.encodeControlValue()

     func (self TYPE) encodeControlValue(){
        self.controlValue = encoder.encode(
            SDFlagsControlValue().setComponents(self.flags))

     func (self TYPE) decodeControlValue(){
        decodedControlValue, _ = decoder.decode(self.controlValue, asn1Spec=SDFlagsControlValue())
        self._flags =  decodedControlValue[0]
        return decodedControlValue

     func (self TYPE) getCriticality(){
        return self.criticality

     func (self TYPE) setCriticality(value interface{}){
        self.criticality = value

     func (self TYPE) getFlags(){
        self.decodeControlValue()
        return self._flags

     func (self TYPE) setFlags(value interface{}){
        self._flags = value
        self.encodeControlValue()

 type SimplePagedResultsControlValue struct { // univ.Sequence:
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('size', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, maxInt))),
        namedtype.NamedType('cookie', univ.OctetString()),
    }


 type SimplePagedResultsControl struct { // Control:
     func (self TYPE) __init__(criticality=nil, size=1000, cookie='', **kwargs interface{}){
        Control.__init__(self, **kwargs)
        self.controlType = CONTROL_PAGEDRESULTS
        if criticality is not nil {
            self.criticality = criticality
        self._size = size
        self._cookie = cookie
        self.encodeControlValue()

     func (self TYPE) encodeControlValue(){
        self.controlValue = encoder.encode(SimplePagedResultsControlValue().setComponents(self._size, self._cookie))

     func (self TYPE) decodeControlValue(){
        decodedControlValue, _ = decoder.decode(self.controlValue, asn1Spec=SimplePagedResultsControlValue())
        self._size, self._cookie = decodedControlValue[0], decodedControlValue[1]
        return decodedControlValue

     func (self TYPE) getCriticality(){
        return self.criticality

     func (self TYPE) setCriticality(value interface{}){
        self.criticality = value

     func (self TYPE) getSize(){
        self.decodeControlValue()
        return self._size

     func (self TYPE) setSize(value interface{}){
        self._size = value
        self.encodeControlValue()

     func (self TYPE) getCookie(){
        self.decodeControlValue()
        return self._cookie

     func (self TYPE) setCookie(value interface{}){
        self._cookie = value
        self.encodeControlValue()


KNOWN_CONTROLS[CONTROL_PAGEDRESULTS] = SimplePagedResultsControl
KNOWN_CONTROLS[CONTROL_SDFLAGS] = SDFlagsControl

 type LDAPMessage struct { // DefaultSequenceAndSetBaseMixin, univ.Sequence:
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('messageID', MessageID()),
        namedtype.NamedType('protocolOp', univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('bindRequest', BindRequest()),
            namedtype.NamedType('bindResponse', BindResponse()),
            namedtype.NamedType('unbindRequest', UnbindRequest()),
            namedtype.NamedType('searchRequest', SearchRequest()),
            namedtype.NamedType('searchResEntry', SearchResultEntry()),
            namedtype.NamedType('searchResDone', SearchResultDone()),
            namedtype.NamedType('searchResRef', SearchResultReference()),
            namedtype.NamedType('modifyRequest', ModifyRequest()),
            namedtype.NamedType('modifyResponse', ModifyResponse()),
            namedtype.NamedType('addRequest', AddRequest()),
            namedtype.NamedType('addResponse', AddResponse()),
            namedtype.NamedType('delRequest', DelRequest()),
            namedtype.NamedType('delResponse', DelResponse()),
            namedtype.NamedType('modDNRequest', ModifyDNRequest()),
            namedtype.NamedType('modDNResponse', ModifyDNResponse()),
            namedtype.NamedType('compareRequest', CompareRequest()),
            namedtype.NamedType('compareResponse', CompareResponse()),
            namedtype.NamedType('abandonRequest', AbandonRequest()),
            namedtype.NamedType('extendedReq', ExtendedRequest()),
            namedtype.NamedType('extendedResp', ExtendedResponse()),
            namedtype.NamedType('intermediateResponse', IntermediateResponse())
        })),
        namedtype.OptionalNamedType(
            'controls',
            Controls().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        },
        // fix AD nonconforming to RFC4511
        namedtype.OptionalNamedType(
            'responseName',
            LDAPOID().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))
        },
        namedtype.OptionalNamedType(
            'responseValue',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11))
        }
    }
