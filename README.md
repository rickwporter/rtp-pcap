# rtp-pcap

C++ tool for looking at RTP in PCAP file.

## Usage

The usage of the compiled program looks like:

```shell
$ ./rtp-pcap --help

rtp-pcap usage:

  rtp-pcap <action> --file <file> [arguments]

  Actions             
          list : List all RTP streams
       summary : Summarize the RTP stream
       details : Provide RTP packet details

  list arguments      
      --odd           : Include odd # ports in list (default only considers even)
      --all           : Print all UDP packets (not just suspected RTP)

  Common arguments    
      --file  <file>  : PCAP file
      --filter <dst|src>: Flag to filter on source/destination IP/UDP (default dst)
      --ip    <addr>  : Source/destination IP address
      --port  <num>   : Source/destination UDP port
      --rtpmap <num=string[:num=string[...]]>: RTP payload type to string values
      --help          : This message

  details arguments   
      --all           : Print all packets in stream
      --quiet         : Do NOT provide analysis comments on stream
      --index <pcap|stream>: Index type (default is stream)
      --time  <none|previous|capture|timeofday|date>: Time display format (default=none)
      --dtmf  <num>   : RTP payload type for DTMF decodes (default=101)
$
```

It can be used to provide analysis of RTP streams from a PCAP file.

Here's a quick example of examing a PCAP:
```shell
$ ./rtp-pcap list --file examples/sip-rtp-g729a.pcap 

rtp-pcap found (433 total packet in capture):
  IP destination: 10.0.2.20:6000 (425 packets)
    SSRCs (1):
      0x044559a1 : 425
    Payload types (1):
      g729 (18) : 425
$ ./rtp-pcap details --file examples/sip-rtp-g729a.pcap --port 6000
     6  Payload type=g729(18), SSRC=0x044559A1, Seq=61831, Time=160, Mark, payload bytes=20
     7-430  Payload type=g729(18), SSRC=0x044559A1, Seq=61832-62254, Time=160 samples/pkt
   430  Payload type=g729(18), SSRC=0x044559A1, Seq=62255, Time=68000, payload bytes=20
$ 

```

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


## Contributing

Contributions are welcome. Please open a pull request with your changes.
The `make format` command was setup to do the formatting according to project standards, so please use it.
