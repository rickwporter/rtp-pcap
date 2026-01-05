#!/usr/bin/env bash
APP=./rtp-pcap
EXAMPLES=examples
TEST_RESULT=0

check_result() {
    description=$1
    expected_result=$2
    expected_output=$3
    actual_result=$4
    actual_output=$5
    
    if [[ $expected_result -ne $actual_result ]]; then
        echo "FAIL: $description result actual($actual_result) not equal to expected($expected_result)"
        TEST_RESULT+=1
    fi

    if [[ "$actual_output" == *"$expected_output"* ]]; then
        echo "PASS: $description"
    else
        echo "FAIL: $description does not contain expected output"
        echo "actual: $actuat_output"
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

check_result "Basic help" 0 "$HELP_START" $result "$output"

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

check_result "L16 list" 0 "$L16_LIST" $result "$output"


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

set -x
output=$($APP details --file $EXAMPLES/sip-rtp-l16.pcap --port 6000 --rtpmap 99=l16 2>&1)
result=$?

check_result "L16 details" 0 "$L16_DETAILS" $result "$output"


#################################################
# G729 all
G729_ALL="     6      0 Payload type=g729(18), SSRC=0x044559A1, Seq=61831, Time=160, Mark, payload bytes=20
     7     19 Payload type=g729(18), SSRC=0x044559A1, Seq=61832, Time=320, payload bytes=20
     8     20 Payload type=g729(18), SSRC=0x044559A1, Seq=61833, Time=480, payload bytes=20
     9     19 Payload type=g729(18), SSRC=0x044559A1, Seq=61834, Time=640, payload bytes=20"

output=$($APP details --file $EXAMPLES/sip-rtp-g729a.pcap --port 6000 --all --time previous 2>&1)
result=$?

check_result "G729 all" 0 "$G729_ALL" $result "$output"

#################################################
# SRTP decrypt
SRTP_DECRYPT="rtp-pcap: decrypt results
    AES-CM-128-SHA1-80bit key[30]=69206b6e6f7720616c6c20796f7572206c6974746c652073656372657473
    srtp failures=0
    wrote 11888 packets to output.pcap"

output=$($APP decrypt --file $EXAMPLES/marseillaise-srtp.pcap --key aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz --alg aes128-sha1-80 --force 2>&1)
result=$?

check_result "SRTP decrypt" 0 "$SRTP_DECRYPT" $result "$output"

#################################################
# Final
exit $TEST_RESULT
