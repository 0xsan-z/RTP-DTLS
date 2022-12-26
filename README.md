# RTP-DTLS
Send RTP over DTLS

# How to run
Server: ./dtls_rtp -V -L 127.0.0.1 -p 65000
Client: ./dtls_rtp -V -p 65000 -n 2 127.0.0.1
      : openssl s_client -dtls -connect 127.0.0.1:65000 -debug
