SIP/2.0 407 Proxy Authentication Required
Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds
From: Alice <sip:alice@example.com>;tag=1928301774
To: Bob <sip:bob@example.com>;tag=a6c85cf
Call-ID: a84b4c76e66710@pc33.example.com
CSeq: 314159 INVITE
Proxy-Authenticate: Digest realm="example.com", domain="sip:ss1.example.com", nonce="f84f1cec41e6cbe5aea9c8e88d359", opaque="", stale=FALSE, algorithm=MD5
Content-Length: 0

