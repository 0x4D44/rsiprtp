REGISTER sip:example.com SIP/2.0
Via: SIP/2.0/UDP host5.example.com;branch=z9hG4bKfirst
To: sip:user@example.com
From: sip:user@example.com;tag=first
Max-Forwards: 8
Call-ID: dblreq.0ha0isndaksdj@host5.example.com
CSeq: 8 REGISTER
Contact: <sip:user@host5.example.com>
Content-Length: 0

INVITE sip:other@example.com SIP/2.0
Via: SIP/2.0/UDP host5.example.com;branch=z9hG4bKtrailing
Content-Length: 0

