# rtp-pcap

C++ tool for looking at RTP in PCAP file.

## Usage

The usage of the compiled program looks like:

```shell
$ ./rtp-pcap --help
Look at RTP in a PCAP file


rtp-pcap [OPTIONS] SUBCOMMANDS


OPTIONS:
  -h,     --help              Print this help message and exit

SUBCOMMANDS:
  list                        List all RTP streams
  summary                     Summarize the RTP stream
  details                     Provide RTP packet details
  stats                       Provide RTP packet statistics for a stream
  encrypt                     Encrypt single RTP stream to another PCAP
  decrypt                     Decrypt single RTP stream to another PCAP

Use "rtp-pcap <action> --help" for action argument info.

$ ./rtp-pcap details --help
Provide RTP packet details


rtp-pcap details [OPTIONS] file


POSITIONALS:
  file TEXT REQUIRED          PCAP file

OPTIONS:
  -h,     --help              Print this help message and exit
          --filter TEXT:{dst,src} [dst]
                              Flag to filter on source or destination IP/UDP (default dst)
          --ip addr           Source or destination IP address
          --port num          Source or destination UDP port
          --rtpmap num=string[:num=string[...]]
                              RTP payload type to string values
          --all               Print all packets in stream
          --quiet             Do NOT provide analysis comments on stream
          --index TEXT:{pcap,stream} [pcap]
                              Index type (default pcap)
          --time TEXT:{none,previous,capture,timeofday,date} [none]
                              Time display format (default none)
          --dtmf INT:INT in [0 - 127] [101]
                              RTP payload type for DTMF decodes (default 101)
$
```

Flag names and keyword values (`dst`/`src`, time formats, index types, and SRTP algorithms) are case-insensitive. File names, IP addresses, and keys keep the case you type.

It can be used to provide analysis of RTP streams from a PCAP file.

Here's a quick example of examing a PCAP:
```shell
$ ./rtp-pcap list examples/sip-rtp-g729a.pcap 

rtp-pcap found (433 total packet in capture):
  IP destination: 10.0.2.20:6000 (425 packets)
    SSRCs (1):
      0x044559a1 : 425
    Payload types (1):
      g729 (18) : 425
$ ./rtp-pcap details examples/sip-rtp-g729a.pcap --port 6000
     6  Payload type=g729(18), SSRC=0x044559A1, Seq=61831, Time=160, Mark, payload bytes=20
     7-430  Payload type=g729(18), SSRC=0x044559A1, Seq=61832-62254, Time=160 samples/pkt
   430  Payload type=g729(18), SSRC=0x044559A1, Seq=62255, Time=68000, payload bytes=20
$ 
```

Here's a quick example of decrypting an encrypted SRTP stream:
```shell
#
# Look at the encrypted stream
#
$ ./rtp-pcap details examples/marseillaise-srtp.pcap 
     1  Payload type=pcma(8), SSRC=0xDEADBEEF, Seq=0, Time=0, Mark, payload bytes=170
     2-11888  Payload type=pcma(8), SSRC=0xDEADBEEF, Seq=1-11886, Time=160 samples/pkt
 11888  Payload type=pcma(8), SSRC=0xDEADBEEF, Seq=11887, Time=1901920, payload bytes=170

#
# Decrypt the stream to a new file
#
$ ./rtp-pcap decrypt examples/marseillaise-srtp.pcap --key aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz --alg aes128-sha1-80 --output decrypted.pcap


rtp-pcap: decrypt results
    AES-CM-128-SHA1-80bit key[30]=69206b6e6f7720616c6c20796f7572206c6974746c652073656372657473
    srtp failures=0
    wrote 11888 packets to decrypted.pcap

#
# Look at the decrypted stream
#
$ ./rtp-pcap details decrypted.pcap 
     1  Payload type=pcma(8), SSRC=0xDEADBEEF, Seq=0, Time=0, Mark, payload bytes=160
     2-11888  Payload type=pcma(8), SSRC=0xDEADBEEF, Seq=1-11886, Time=160 samples/pkt
 11888  Payload type=pcma(8), SSRC=0xDEADBEEF, Seq=11887, Time=1901920, payload bytes=160
$ 
```

The payload lengths in the above example can be seen to have shrunk by 10 bytes per packet (which is the 80-bit authentication trailer). If you open the `decrypted.pcap`, you can see the PCMA voice data is considerably less "random" than the original.


## Development

The project is a C++ source code project.
It uses `make` to build the source code, and `make` provides the help to identify most of the targets.
Currently, it has only been tested on an X86 MAc.

### Prerequisites

There are a few requirements to build the project:
* `g++` compiler 
* `clang-format` linter
* Libraries (installed)
    * `libpcap` used for parsing packets from file
    * `libsrtp2` used for encrypting/decrypting packets from file
* [CLI11](https://github.com/CLIUtils/CLI11) 2.7.2 for command-line parsing, vendored at `third_party/CLI11/include/CLI/CLI.hpp`


## Contributing

Contributions are welcome. Please open a pull request with your changes.
The `make format` command was setup to do the formatting according to project standards, so please use it.
