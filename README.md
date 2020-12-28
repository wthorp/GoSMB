# GoSMB
SMB server written in Go

This document is laying out a plan for implementing an SMB server entirely in Go.

## Potential methods
1. Transpile existing implementation to Go
2. Hand port existing implementation to Go
3. Build Go implementation from scratch using existing Go libraries
4. The most likely solution : some combination of the above

## Likely relavent Go Code
* [stacktitan/smb](https://github.com/stacktitan/smb)
* [go-ntlmssp](https://github.com/Azure/go-ntlmssp)
* [gokrb5](https://github.com/jcmturner/gokrb5)


## Reference texts
* https://en.wikipedia.org/wiki/Server_Message_Block
* https://en.wikipedia.org/wiki/NetBIOS
* https://www.samba.org/ftp/tridge/misc/french_cafe.txt
* https://www.samba.org/ftp/samba/specs/
* TODO:  more here

## Minimum viable target
* SMB can run on TCP without NETBIOS.  I can't find a Go NETBIOS library, so it may be easier without it.
* TODO:  more here

## Impacket
[Impacket](https://github.com/SecureAuthCorp/impacket) is interesting for a few of reasons.  
1. Its written in Python and the [Grumpy](https://github.com/google/grumpy) transpiler is well known.
2. Impacket was authored for pen-testing and has some other interesting protocols / code.
3. The Python [grammar](https://docs.python.org/3/reference/grammar.html) is well documented.

### Transpiling with Grumpy

Initial attempts at transpiling via Grumpy were slow going.
The codebase uses eval(), various "futures", and other features known to not work with Grumpy.
No support for the crucial [struct](https://docs.python.org/2/library/struct.html) standard library.

### Transpiling with custom ANTLR4 and go/ast

I've generated code with go/ast before.  I was able to generate Go code from the Python grammar using ANTLR4.  
The volume of things it generated was a little overwhelming, and I didn't really try to understand it.
I'm wondering if goyacc might be simpler.

### Hand Porting

The impacket codebase relies heavily on [struct](https://docs.python.org/2/library/struct.html) packing.
It uses a string syntax to identify serialization characteristic and default values.
In most cases, this struct syntax ports trivially, EG:
`('InputCount','<L=0')` becomes `InputCount uint32`.
However, in some cases these string contain logic to be evaluated at runtime, EG:
`('OutputOffset','<L=(self.SIZE + 64 + len(self["AlignPad"]) + self["InputCount"])')`

I wrote an [ugly hack](hack.go.old) to see what progress could be made with regular expressions only.
Its a lot of work, and its probably easier to understand and reimplement than do a naive port of the code.

## Reference implementation that might be better options for hand-porting, but that would be terrible for transpiling because their copy-left licenses aren't the kind of thing a Go developer would do

### [Samba](https://github.com/samba-team/samba) is interesting for a couple of reasons.
1. Its the most well known and thus probably best tested open source SMB server.
2. [c2go](https://github.com/andybalholm/c2go) would be amazing, but [SWIG](http://www.swig.org/) etc may help

### [JCIFS](https://www.jcifs.org/)
1. Hey, it's Java!  I don't know, maybe that means its well structured?
2. Maybe there's a [JSweet](http://www.jsweet.org/) + [godzilla](https://github.com/jingweno/godzilla) path?
