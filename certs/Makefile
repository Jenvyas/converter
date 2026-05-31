days = 365

new_cert = config/certs.conf ca

allcerts: ca converter1 converter2 etsi_server1 etsi_server2

.PHONY: certs clean converter1 converter2 etsi_server1 etsi_server2

ca: ca.cert.pem ca.key.pem

ca.cert.pem ca.key.pem &: config/certs.conf
	openssl req -config config/certs.conf -new -x509 -newkey rsa:4096 -noenc -keyout ca.key.pem -days $(days) -out ca.cert.pem -batch

converter1: converter1.cert.pem converter1.key.pem

converter1.cert.pem converter1.key.pem &: $(new_cert)
	openssl req -noenc -newkey rsa:4096 -keyout converter1.key.pem -out converter1.req -sha256 -batch -subj "/CN=localhost"
	openssl x509 -req -in converter1.req -out converter1.cert.pem -CA ca.cert.pem -CAkey ca.key.pem -sha256 -days $(days) -set_serial 1 \
		-extensions v3_converter1 -extfile config/certs.conf
	rm converter1.req

converter2: converter2.cert.pem converter2.key.pem

converter2.cert.pem converter2.key.pem &: $(new_cert)
	openssl req -noenc -newkey rsa:4096 -keyout converter2.key.pem -out converter2.req -sha256 -batch -subj "/CN=localhost"
	openssl x509 -req -in converter2.req -out converter2.cert.pem -CA ca.cert.pem -CAkey ca.key.pem -sha256 -days $(days) -set_serial 2 \
		-extensions v3_converter2 -extfile config/certs.conf
	rm converter2.req

etsi_server1: etsi_server1.cert.pem etsi_server1.key.pem

etsi_server1.cert.pem etsi_server1.key.pem &: $(new_cert)
	openssl req -noenc -newkey rsa:4096 -keyout etsi_server1.key.pem -out etsi_server1.req -sha256 -batch -subj "/CN=localhost"
	openssl x509 -req -in etsi_server1.req -out etsi_server1.cert.pem -CA ca.cert.pem -CAkey ca.key.pem -sha256 -days $(days) -set_serial 3 \
		-extensions v3_etsi_server1 -extfile config/certs.conf
	rm etsi_server1.req

etsi_server2: etsi_server2.cert.pem etsi_server2.key.pem

etsi_server2.cert.pem etsi_server2.key.pem &: $(new_cert)
	openssl req -noenc -newkey rsa:4096 -keyout etsi_server2.key.pem -out etsi_server2.req -sha256 -batch -subj "/CN=localhost"
	openssl x509 -req -in etsi_server2.req -out etsi_server2.cert.pem -CA ca.cert.pem -CAkey ca.key.pem -sha256 -days $(days) -set_serial 4 \
		-extensions v3_etsi_server2 -extfile config/certs.conf
	rm etsi_server2.req


clean:
	-rm -f *.pem



