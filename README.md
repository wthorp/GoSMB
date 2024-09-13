# GoSMB
A work-in-progress SMB server written in Go.
I hope to dust this off after years of neglect.

## Design Goals
* Permissive MIT-style licensing.
* Support for SMB over TCP and eventually QUIC.
* Compatibility with latest MacOS and Windows OS.
* Support for some secure type of login in addition to guest.
* Aggressive upgrading negotitation of the most recent protocols which support the above goals.
* Not implementing any features not necessary to obtain the above goals.

## Methodology
SMB contains a lot of legacy features and backward compatibility logic.  Its difficult to
develop working parts in situ without falling back to some functional complete solution.  There's 
a temptation to create a one-shot port of existing solutions, but differences in 3rd party 
libraries make this nearly impossible.

To make this easier and avoid needing external tools, the methology employed here is to create
a dumb proxy first.  One by one, different parts of the protocol may be swapped out, thus using 
the strangler pattern to create a full SMB implementation and eventually removing the proxy.

## Likely Relavent Go Code
* [stacktitan/smb](https://github.com/stacktitan/smb)
* [alessandrovaprio/go-smb-client](https://github.com/alessandrovaprio/go-smb-client)
* [Amzza0x00/go-impacket](https://github.com/Amzza0x00/go-impacket)
* [CloudSoda/go-smb2](https://github.com/CloudSoda/go-smb2)
* [gavriva/smb2](https://github.com/gavriva/smb2)
* [gentlemanautomaton/smb](https://github.com/gentlemanautomaton/smb)
* [hirochachacha/go-smb2](https://github.com/hirochachacha/go-smb2)
* [hy05190134/smb2proxy](https://github.com/hy05190134/smb2proxy)
* [izouxv/smbapi](https://github.com/izouxv/smbapi)
* [PichuChen/simba](https://github.com/PichuChen/simba)
* [Xmister/libsmb2-go](https://github.com/Xmister/libsmb2-go)
* [xpn/ntlmquic](https://github.com/xpn/ntlmquic)
* [Azure/go-ntlmssp](https://github.com/Azure/go-ntlmssp)
* [jcmturner/gokrb5](https://github.com/jcmturner/gokrb5)

## Non-Go SMB Server implementations
* https://github.com/SecureAuthCorp/impacket
* https://github.com/samba-team/samba
* https://www.jcifs.org/
* https://github.com/cifsd-team/ksmbd

## Reference texts
* https://en.wikipedia.org/wiki/Server_Message_Block
* https://en.wikipedia.org/wiki/NetBIOS
* https://www.samba.org/ftp/tridge/misc/french_cafe.txt
* https://www.samba.org/ftp/samba/specs/
* https://gist.github.com/jbfriedrich/49b186473486ac72c4fe194af01288be
* https://support.apple.com/en-us/102050

## Development Notes
MacOS Finder does some sort of caching of SMB results.  While it is an integration target, 
it's not really worth relying on Finder's "Connect to Server" functionality for actively 
developing solutions.
