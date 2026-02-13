#!/usr/bin/env bash
APP=./rtp-pcap
EXAMPLES=examples
TEST_RESULT=0

check_substring() {
    local description=$1
    local expected=$2
    local actual=$3
    
    if [[ "$actual" == *"$expected"* ]]; then
        echo "PASS: $description"
    else
        echo "FAIL: $description does not contain expected output"
        echo "actual:\n$actual"
        TEST_RESULT+=1
    fi
}

check_result() {
    local description=$1
    local expected=$2
    local actual=$3
    
    if [[ $expected -ne $actual ]]; then
        echo "FAIL: $description result actual($actual) not equal to expected($expected)"
        TEST_RESULT+=1
    fi
}

#################################################
# Basic help
HELP_START="  rtp-pcap <action> --file <file> [arguments]

  Actions             
          list : List all RTP streams
       summary : Summarize the RTP stream
       details : Provide RTP packet details
       encrypt : Encrypt single RTP stream to another PCAP
       decrypt : Decrypt single RTP stream to another PCAP
"

output=$($APP --help 2>&1)
result=$?

check_result "Basic help" 0 $result
check_substring "Basic help" "$HELP_START" "$output"


#################################################
# L16 list
L16_LIST="rtp-pcap found (1673 total packet in capture):
  IP destination: 10.0.2.20:6000 (1641 packets)
    SSRCs (4):
      0x043da974 : 425
      0x043da985 : 366
      0x043ffa0c : 425
      0x043ffa21 : 425
    Payload types (1):
      unknown (99) : 1641"

output=$($APP list --file $EXAMPLES/sip-rtp-l16.pcap 2>&1)
result=$?

check_result "L16 list" 0 $result
check_substring "L16 list" "$L16_LIST" "$output"


#################################################
# L16 details
L16_DETAILS="     6  Payload type=l16(99), SSRC=0x043DA974, Seq=20376, Time=160, Mark, payload bytes=640
     7-430  Payload type=l16(99), SSRC=0x043DA974, Seq=20377-20799, Time=160 samples/pkt
   430  Payload type=l16(99), SSRC=0x043DA974, Seq=20800, Time=68000, payload bytes=640
***** SSRC changed from 71149940 to 71301644 ******
   439  Payload type=l16(99), SSRC=0x043FFA0C, Seq=50505, Time=320, Mark, payload bytes=1280
   440-863  Payload type=l16(99), SSRC=0x043FFA0C, Seq=50506-50928, Time=320 samples/pkt
   863  Payload type=l16(99), SSRC=0x043FFA0C, Seq=50929, Time=136000, payload bytes=1280
***** SSRC changed from 71301644 to 71149957 ******
   872  Payload type=l16(99), SSRC=0x043DA985, Seq=14108, Time=256, Mark, payload bytes=512
   873-1237  Payload type=l16(99), SSRC=0x043DA985, Seq=14109-14472, Time=256 samples/pkt
  1237  Payload type=l16(99), SSRC=0x043DA985, Seq=14473, Time=93696, payload bytes=512
***** SSRC changed from 71149957 to 71301665 ******
  1246  Payload type=l16(99), SSRC=0x043FFA21, Seq=50794, Time=960, Mark, payload bytes=1920
  1247-1670  Payload type=l16(99), SSRC=0x043FFA21, Seq=50795-51217, Time=960 samples/pkt
  1670  Payload type=l16(99), SSRC=0x043FFA21, Seq=51218, Time=408000, payload bytes=1920"

output=$($APP details --file $EXAMPLES/sip-rtp-l16.pcap --port 6000 --rtpmap 99=l16 2>&1)
result=$?

check_result "L16 details" 0 $result
check_substring "L16 details" "$L16_DETAILS" "$output"


#################################################
# G726 details

# NOTE: the sequence rollover in the first SSRC
G726_DETAILS="***** SSRC changed from 71150055 to 71301759 ******
  2171  Payload type=unknown(99), SSRC=0x043FFA7F, Seq=65433, Time=160, Mark, payload bytes=60
  2172-2595  Payload type=unknown(99), SSRC=0x043FFA7F, Seq=65434-320, Time=160 samples/pkt
  2595  Payload type=unknown(99), SSRC=0x043FFA7F, Seq=321, Time=68000, payload bytes=60
***** SSRC changed from 71301759 to 71150072 ******
  2604  Payload type=unknown(99), SSRC=0x043DA9F8, Seq=11987, Time=160, Mark, payload bytes=80
  2605-3028  Payload type=unknown(99), SSRC=0x043DA9F8, Seq=11988-12410, Time=160 samples/pkt
  3028  Payload type=unknown(99), SSRC=0x043DA9F8, Seq=12411, Time=68000, payload bytes=80"

output=$($APP details --file $EXAMPLES/sip-rtp-g726.pcap 2>&1)
result=$?

check_result "G726 details" 0 $result
check_substring "G726 details" "$G726_DETAILS" "$output"

#################################################
# G729 all
G729_ALL="     6      0 Payload type=g729(18), SSRC=0x044559A1, Seq=61831, Time=160, Mark, payload bytes=20
     7     19 Payload type=g729(18), SSRC=0x044559A1, Seq=61832, Time=320, payload bytes=20
     8     20 Payload type=g729(18), SSRC=0x044559A1, Seq=61833, Time=480, payload bytes=20
     9     19 Payload type=g729(18), SSRC=0x044559A1, Seq=61834, Time=640, payload bytes=20"

output=$($APP details --file $EXAMPLES/sip-rtp-g729a.pcap --port 6000 --all --time previous 2>&1)
result=$?

check_result "G729 all" 0 $result
check_substring "G729 all" "$G729_ALL" "$output"


#################################################
# iLBC summary
ILBC_SUMMARY="rtp-pcap summary:
  IP destination: 10.0.2.20:6000
  RTP 284 packets (292 in capture)
  SSRCs (1):
    0x043eefa7 : 284
  Payload types (1):
    unknown (99) : 284"

output=$($APP summary --file $EXAMPLES/sip-rtp-ilbc.pcap 2>&1)
result=$?

check_result "iLBC summary" 0 $result
check_substring "iLBC summary" "$ILBC_SUMMARY" "$output"


#################################################
# SRTP decrypt (base64)
SRTP_DECRYPT="rtp-pcap: decrypt results
    AES-CM-128-SHA1-80bit key[30]=69206b6e6f7720616c6c20796f7572206c6974746c652073656372657473
    No srtp failures
    wrote 11888 packets to output.pcap"

output=$($APP decrypt --file $EXAMPLES/marseillaise-srtp.pcap --key aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz --alg aes128-sha1-80 --force 2>&1)
result=$?

check_result "SRTP decrypt (base64)" 0 $result
check_substring "SRTP decrypt (base64)" "$SRTP_DECRYPT" "$output"


#################################################
# SRTP decrypt (hex)
SRTP_DECRYPT_SUMMARY="rtp-pcap: decrypt results
    AES-CM-128-SHA1-80bit key[30]=69206b6e6f7720616c6c20796f7572206c6974746c652073656372657473
    No srtp failures
    wrote 11888 packets to output.pcap"
SRTP_DECRYPT_DEBUG="SRTP-LOG [3]: srtp: function srtp_unprotect
SRTP-LOG [3]: srtp: estimated u_packet index: 0000000000002e6f
SRTP-LOG [3]: srtp: estimated u_packet index: 0000000000002e6f"

output=$($APP decrypt --file $EXAMPLES/marseillaise-srtp.pcap --key 69206b6e6f7720616c6c20796f7572206c6974746c652073656372657473 --alg aes128-sha1-80 --debug --force 2>&1)
result=$?

check_result "SRTP decrypt (hex)" 0 $result
check_substring "SRTP decrypt (hex) summary" "$SRTP_DECRYPT_SUMMARY" "$output"
check_substring "SRTP decrypt (hex) debug" "$SRTP_DECRYPT_DEBUG" "$output"


#################################################
# SRTP decrypt (bad alg)
SRTP_DECRYPT="rtp-pcap: decrypt results
    AES-CM-128-SHA1-32bit key[30]=69206b6e6f7720616c6c20796f7572206c6974746c652073656372657473
    11888 srtp failures:
        authentication failure: 11888   
    wrote 0 packets to output.pcap"

output=$($APP decrypt --file $EXAMPLES/marseillaise-srtp.pcap --key 69206b6e6f7720616c6c20796f7572206c6974746c652073656372657473 --force 2>&1)
result=$?

check_result "SRTP decrypt (bad)" 0 $result
check_substring "SRTP decrypt (bad)" "$SRTP_DECRYPT" "$output"


#################################################
# Final
exit $TEST_RESULT
