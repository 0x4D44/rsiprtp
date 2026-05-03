REGISTER sip:registrar.example.com SIP/2.0
Via: SIP/2.0/UDP bobspc.example.com:5060;branch=z9hG4bKnashds7
Max-Forwards: 70
To: Bob <sip:bob@example.com>
From: Bob <sip:bob@example.com>;tag=456248
Call-ID: 843817637684230@998sdasdh09
CSeq: 1826 REGISTER
Contact: <sip:bob@bobspc.example.com:5060>;expires=3600
Authorization: Digest username="bob", realm="example.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="sip:registrar.example.com", response="6629fae49393a05397450978507c4ef1"
Content-Length: 0

