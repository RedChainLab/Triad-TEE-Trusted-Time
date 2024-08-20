# Code d'un noeud Triad

## Compilation
dans le dossier server (qui n'a plus de raison de s'appeler comme ça)

make

## Execution
Dans trois cmdline : 

`host/tls_server_host ./enc/tls_server_enclave.signed.so 12340 12341 12342 2 3 19 20`
`host/tls_server_host ./enc/tls_server_enclave.signed.so 12341 12340 12342 4 5 21 22`
`host/tls_server_host ./enc/tls_server_enclave.signed.so 12342 12341 12340 6 7 23 24`

`host/tls_server_host <own_port> <other_node1_port> <other_node2_port> <core_id_readTSC> <core_id_add> <core_id_server> <core_id_client>`

le -server-in-loop ne sert plus faut que je l'enlève de host.cpp
le premier port est celui de du noeud que tu lances, les deux suivants sont les ports des autres noeuds 