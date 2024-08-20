## Compilation
dans le folder build
make

## Certificats
Dans build:
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes

## Exécution
`./MultiNodeTLS <own_port> <node1_port> <node2_port> <node3_port>`
`./MultiNodeTLS 12350 12340 12341 12342`