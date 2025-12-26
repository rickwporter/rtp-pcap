#pragma once

/*******************************************/
/** RTP and RTP-EVENT (RFC-2833) structure definitions **/
/*******************************************/

/* Bit fields in first 32-bit word of RTP header */

typedef struct {
    uint32_t cc:4;      /* # of CSRC identifiers       */
    uint32_t x:1;       /* # of extension headers      */
    uint32_t p:1;       /* Is there padding appended   */
    uint32_t v:2;       /* version                     */
    uint32_t pt:7;      /* payload type                */
    uint32_t m:1;       /* marker bit                  */
    uint32_t seqnum:16; /* sequence number             */
} rtpbits_t;

typedef struct { /* Note : assumes network byte order */
    rtpbits_t b;
    uint32_t timestamp; /* timestamp                  */
    int ssrc;           /* Synchronization Source     */
    char payload[];     /* Assumes cc is 0            */
} rtphdr_t;

typedef struct {
    uint32_t event:8;     /* DTMF Digit or Telephony Event */
    uint32_t volume:6;    /* Volume of tone                */
    uint32_t reserved:1;  /* Reserved for future           */
    uint32_t e:1;         /* End bit indicator             */
    uint32_t duration:16; /* Duration of tone              */
} rtp_event_t;
