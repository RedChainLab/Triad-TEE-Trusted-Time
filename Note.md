# Note sur SSL/TLS

## Commande 

sudo docker run -it -v /home/jean/Jean/ENSTA/2A/LIRIS/docker/SGX/own_sgx_prg/SampleAttestedTLS:/SGX sgx-sim /bin/bash
. /opt/intel/sgxsdk/environment

## Contexte SSL

Un contexte SSL contient les infos nécessaires pour créer des connexions SSL/TLS, par exemple:
- les méthodes de chiffrages
- les options de config des ciphers
- les paramètres de vérification des certificats...

Dans la lib openSSL, les contextes sont des objets de type **SSL_CTX** 


## Côté Client

- On commence par initialiser un contexte : 

`̀`̀ cpp
SSL_CTX* ssl_client_ctx = nullptr;
if ((ssl_client_ctx = SSL_CTX_new(TLS_client_method())) == nullptr)
{
    t_print(TLS_CLIENT "unable to create a new SSL context\n");
    goto done;
}
`̀ `

`TLS_client_method()` cette fonction est utilisée pour initialiser le contexte 

- Une fois que l'on a créer et initialisé un contexte, on peut le configurer à l'aide d'un objet de type **SSL_CONF_CTX**. J'ai l'impression que c'est 
fait de manière un peu custom dans `openssl_client.cpp` avec la fonction `initalize_ssl_context` 

- La prochaine étape dans `openssl_client.cpp` est la vérification du certificat : ̀`SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_PEER, &verify_callback);`, une fonction de callback custom est spécifiée, `verify_callback`. Elle check le certificat dans l'enclave.

- Une fois le certificat vérifié (de ce que je comprend, celui du serveur), on génère une clef privé et un certificat pour le client. Le tout dans l'enclave : 

```cpp
if (load_tls_certificates_and_keys(ssl_client_ctx, cert, pkey) != 0)
{
    t_print(TLS_CLIENT
            " unable to load certificate and private key on the client\n");
    goto done;
}
```

- à partir du contexte, on peut créer une session SSL. 

```cpp
if ((ssl_session = SSL_new(ssl_client_ctx)) == nullptr)
{
    t_print(TLS_CLIENT
            "Unable to create a new SSL connection state object\n");
    goto done;
}
```

- Ensuite on défini le file descriptor de la connexion SSL

```cpp
if ((error = SSL_connect(ssl_session)) != 1)
```

- On démarre une communication HTTP avec le serveur

```cpp
if ((error = communicate_with_server(ssl_session)) != 0)
{
    t_print(TLS_CLIENT "Failed: communicate_with_server (ret=%d)\n", error);
    goto done;
}
```


## Côté Serveur
Pareil

## Bilan
Les fichiers `openssl_client.cpp` et `openssl_server.cpp` permettent de démarrer une communication socket entre un client et un serveur et de chiffrer la communication.
En plus de cela, les certificats et les clefs privés sont générés et vérifiés dans une enclave.


## Fichier host.cpp
### Côté client

- Le programme attend 3 paramètre : CLIENT_ENCLAVE_FILENAME, le nom du server, le port 
- On créé une enclave
- On lance la communication TLS

## On test

sudo docker run -it -v /home/jean/Jean/ENSTA/2A/LIRIS/docker/SGX/own_sgx_prg/SampleAttestedTLS:/SGX sgx-sim /bin/bash
. /opt/intel/sgxsdk/environment

## Problèmes

- le fichier sgxenv.mk importe des bibliothèques non installées, destinées à faire l'attestation j'ai commenté ces imports (ligne 95)
- la fonction `tee_get_certificate_with_evidence` ajoute une preuve de l'authenticité de l'enclave avec le mécanisme de remote attestation au certificat, j'ai créé une fonction qui ne génère que le certificat (voir `openssl_utility`)
- le makefile génère automatiquement des fichiers, comme par exemple `tls_server_t.c` qui vérifie les quotes.
- en suivant le fichier tls_client.edl on voit la fonction appelée launch_tls_client qui appelle probablement des trucs chiants.
- la fonction de callback appelée par SSL_CTX_set_verify fait intervenir des mécanismes de vérification de quote : notamment la macro `VERIFY_CALLBACK` qui correspond à `tee_verify_certificate_with_evidence`, je vais créer une version simplifié de cette fonction

- Dans les fonctions `generate_certificate_and_pkey` et `tee_get_self_signed_certificate`, j'ai changé les type de retour en `sgx_status_t`

- j'ai changé p_sgx_tls_qe_err_msg en 

```cpp
void p_sgx_tls_qe_err_msg(sgx_status_t error_code)
{
    PRINT("error code: 0x%x\n", error_code);
}
```

- Il faut faire les même changement côté serveur

- j'ai changé le makefile de `/client/host` et `/server/host` pour qu'ils utilisent des `fake_ocalls`
- ça compile mais je ne eux pas run, une erreur comme quoi aucune device SGX est installée est levée. Pourtant je suis bien en mode SIM

- Dans client/host, l'erreur 0x2006 (sgx_status_t) est levée, cela signifie SGX_ERROR_NO_DEVICE --> pourtant je suis bien en SIM  

- On essaye de passer le SGX_DEBUG à 0 

```makefile
SGX_DEBUG ?= 0#1
```

- changer ca dans .mk
```makefile
Urts_Library_Name := sgx_urts_sim #sgx_urts
U_TLS_Library_Name := sgx_utls_sim #sgx_utls

SGX_TLS_Library_Name := sgx_ttls_sim#sgx_ttls
```
 ---> conduit à une nouvelle erreur, je crois l'avoir vu sur stack overflow 
l'erreur `SGX_ERROR_INCOMPATIBLE` signifie `SGX_ERROR_MODE_INCOMPATIBLE`

https://community.intel.com/t5/Intel-Software-Guard-Extensions/Returns-SGX-ERROR-MODE-INCOMPATIBLE/m-p/1196062
--> ca n'a rien donnée

- certaine lib n'étaient pas chargées dans leur version sim (dans sgxenv.mk): 

```makefile
######## Enclave Settings ########

Trts_Library_Name := sgx_trts_sim #sgx_trts
Service_Library_Name := sgx_tservice_sim #sgx_tservice
```

- l'erreur est levée par la fonction `set_up_tls_server`  dans `/client/host/host.cpp` et idem pour le server. Cette fonction est dans le ficheir `tls_server_u.c` qui est auto-généré avec le makefile. Cette fonction fait un `sgx_ecall` qui cause surement le problème. 

- explication de ce qui bloque : dans `client/host/host.cpp` la fonction `launch_tls_client` est appelée. Elle se trouve dans le fichier auto-générée `tls_client_u.c`. Cette fonction fait un ecall à `launch_tls_client(char*, char*)`, qui se trouvent dans `openssl_client.cpp`

- je pense que l'erreur vient du fait que je compile avec certaines bibliothèques dans le mode HW et pas SIM

- on essaye sgx-gdb : j'ai du installer gdb dans l'enclave, ensuite 
- cd client/host 
- sgx-gdb ./tls_client_host
- break initialize_enclave
- break sgx_create_enclave 
- break launch_tls_client 
- run ./client/enc/tls_client_enclave.signed.so -server:localhost -port:12341  
- et ensuite on avance avec  des next et des step


Ca fonctionne en mode HW en tout cas
on va essayer d'envoyer des requêtes simples

## Ajout des TS

J'ai ajouté les fonctions pour calc le timestamps dans une enclave, il faut mainteant ajouter cela au fichier .edl --> OK
Ajouter le sealing --> OK
voir comment fonctionne le sealing, et probablement envoyer les clefs de chiffrements dans le TLS
ajouter les GET bien comme il faut pour que le client puisse demander un ts 

Ok dans server/openssl_server.cpp, est définit ce qu'on doit faire suivant le payload que l'on reçoit : 

```cpp
if (write_to_session_peer(
        ssl_session, SERVER_PAYLOAD, strlen(SERVER_PAYLOAD)) != 0)
{
    t_print(TLS_SERVER " Write to client failed\n");
    break;
```

C'est dans la fonction `handle_communication_until_done` qui est appelée par `set_up_tls_server` 

Question : où est ce que l'on définit quoi faire suivant la requête que l'on reçoit ?

la fonction `handl_communication_until_done` appelle `read_from_session_peer` et `write_to_session_peer` dans le fichier `openssl_utility.cpp` je vais donc modifier ces fonctions pour qu'elles tiennent comptes de l'en-tête reçue.

## Comportement du serveur:

pour le moment, si je fais make run, le serveur va simplement :
- préparer une connection SSL/TLS
- attendre le handshake du client
- une fois le handshake réalisé, recevoir le message du client
- envoyer une réponse
- fermer la connexion ssl

si on fait make run-server-in-loop il va faire ca en boucle, autrment dit, la connexion SSL/TLS n'est pas maintenu, elle est refaite à chaque connexion du client au serveur
côté client, il suffit de faire make run depuis le dossier client.

Je pense qu'il faut un peu revoir openssl_utility.cpp, puisqu'il prend en argument un payload et sa taille, donc il doit savoir à l'avance ce qu'il va recevoir sinon il lève une erreur sur la taille 
reçue et la taille attendue (ducoup qui ne coïncice pas forcément)

J'ai ajuster la fonction `read_from_session_peer` dans `openssl_utility.cpp`, on peut maintenant choisir la requête à envoyer depuis `communicate_with_server` définit dans `openssl_client.cpp`

## envoie des timestamps

On va maintenant faire ne sorte que l'on puisse envoyer chercher le timestamps et l'envoyer au client.

- je vais mettre les fonctions pour calc le TSC dans l'enclave du serveur
- je vais ensuite ajouter ces fonctions au fichier .edl de l'enclave serveur
- il va falloir que je place ce code : 
```cpp
uint64_t tsc;
sgx_status_t status = readTSC(global_eid, &tsc);
std::cout << status << std::endl;
if (status != SGX_SUCCESS) {
    std::cout << "fail" << std::endl;
}

std::cout << "TSC: " << tsc << std::endl;
``` 
dans `host.cpp` du server 
- Problème : au moment où l'on recoit une requête du client, il faudrait que l'on calcule le TS et qu'on le mette et/ou qu'on l'envoye au client

- on peut jouer sur la valeur de retour de `read_from_session_peer`, puisque cette fonction est appelée par `openssl_server.cpp` qui est dans l'enclave server.  

- ya un truc chelou sur la definition de readTSC, la fonction ne prend pas d'argument, pourtant je lui en donne, voir ce que j'ai fait dans triad.

- question : est ce qu'on fait appel à `readTSC(global_eid, &tsc)` --> on lui fait appel depuis le code non-enclave, on le met en cache, et suivant le `return_code`, on envoie le ts mis en cache.

- enfait on ne peut pas appeler readTSC depuis le common,


64947496785469
64954934717800

65202087991048
65238638978939

- J'ai rajouter Host_2, la connexion est maintenant symétrique.


## Détecter la sortie de l'enclave

- Le **TCS Thread Control Structure:** C'est une structure de donnée qui permet de gérer les threads entrant, sortant et interrompue de l'enclave. Cette structure stocke les données nécessaires au context switch et permet de mieux isoler les threads exécutant du code de l'enclave des threads exécutant du code untrusted

On spécifie dans le fichier .xml le nombre de thread alloués à l'enclave:
`<TCSNum>2</TCSNum>`
Le TCS contient notamment le :
- **State Save Area SSA** : Une zone de mémoire utilisée pour stocker l'état des registres et d'autres informations de contexte lors des interruptions.
- **Entry Points:** Adresses des points d'entrée utilisés pour entrer dans l'enclave.
- **Thread-specific Data:** Informations spécifiques au thread, comme les identifiants de thread et les informations d'état.  

Explication des EENTER, EEXIT, AEX et ERESUME
Le contexte d'un thread exécutant du code appartenant à une enclave est sauvegardée dans le `SSA` du `TCS` qui s'occupe de ce thread. 

Si une instruction `EAX` est levée, le contexte est sauvegardé à l'index courrant (pointée par `TCS.CSSA` pour current state-save area) du SSA (mettons SSA[0]). et l'index est incrémenté : `TCS.CSSA++`. De cette manière, si Le code untrusted fait appel à l'enclave avec un `EENTER`, et que une deuxième `EAX` est levée, le contexte SSA[0] ne sera pas ecrasé à la sortie (et donc la sauvgarde du contexte pusqu'il sera sauvegardé dans SSA[1] et non pas SSA[0]) avec l'instruction `EEXIT`.
A la différence de `ERESEUME`, `EENTER` ne décrémente pas `TSC.CSSA`  

- j'essaye de créer un handler custom, je l'ai ajouter en tête de la liste des handlers, il est censé être appelé si une exception est levée.

- Pour récpuérer le ts si on est tainted, je voulais appeler le client pour qu'il contacte un autre noeud, le client seal le ts et le server l'unseal pour l'envoyer au client qui demandait le ts. Mais le server est dans l'enclave et je pense que je peux pas faire d'appel system depuis l'enclave. La solution serait de faire un ocall pour que l'app fasse l'appel system

- bon ca ne marche toujours pas, depuis l'encalve server on fait un ocall pour faire un appel system à client qui va récupérer un ts auprès d'un autre node, une fois récupéré l'enclave client seal le ts et fait un ocall pour ecrire un fichier contenant le ts. on reviens à la l'enclave server qui fait un ocall pour lire le fichier et dans son enclave l'unseal. Mais je pense que les enclaves n'ont pas les mêmes clefs de chiffrement déchiffrement parceque j'obtiens une erreur 3001, aka MAC_MISMATCH


- On va changer un peu : faire un ocall pour créer un thread, le thread appel
le code client qui récupère le timestamps

-trouver comment partager des choses entre les threads.

- j'ai copier colelr le code client dans openserver ssl parceque c'était trop chaint de gérer le linkage

## Linkage de la lib switchless

### Dans les Makefiles
- -lsgx_tswitchless dans la `Enclave_Link_Flags` et -lsgx_uswitchless dans la `App_Link_Flags`, à mettre entre -Wl, whole-archive et -Wl, no-whole-archive

- header dans le code untrusted : `#include <sgx_uswitchless.h>`

- EDL attribute `transition_using_threads` doit être postfixé

- il faut appeler `sgx_create_enclave_ex` et pas `sgx_create_enclave` et créer enclave_ex_p

```cpp
int initialize_enclave(const sgx_uswitchless_config_t* us_config)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    const void* enclave_ex_p[32] = { 0 };

    enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = (const void*)us_config;

    ret = sgx_create_enclave_ex(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, enclave_ex_p);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}
```
- Configurer le switchless : 

```cpp
    sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
    us_config.num_uworkers = 2;
    us_config.num_tworkers = 2;
```

## Ce qu'il reste à faire
- bouger lauch_tls_client dans common 
- transmettre le timestamps au 1er node --> ok
- voire si on laisse les comm ouverte --> en cours
- créer un client tout simple --> ok
- pour la calibration --> maintenir la communication ?
- utiliser les AEX Notify
- VerifyCalibration
- timestamps dans cond-runtime ?
- verifier si c'est pas le launch_tls_client qui fait le ecall, et envoyer une seule requête côté client --> non car launch_tls appelé après avoir vérifier aex_count
- voir si les threads 


## Ce qu'il se passe
- Quand j'envoie une requête du client vers le node, un certain nombre de notify aparaissent
    - Voir si c'est pas le switchless qui est en fait compté comme un ocall
    - retarcer le dérouler des opérations, peut être que les ocalls sont fait dans handle communication until done juster avant  
    - Voir si c'est pas le accept qui est bloquant 
    - Essayer de mettre le handler sur un autre thread
    - Essayer de mettre les pointeurs nécessaires au handler dans la struct et initilaiser le handler dans les autres threads


### Resultats
- les AEXNotify n'ont pas l'air fiable, les t_print ne sont pas toujours comptés.
- quand même bizzare que les AEX Notify ne se manifeste pas entre 2 demandes
- les segfaults de temps en temps sont hazardeux

je suis perplexe, dans AEXTest, même en faisant rien ya masse AEX exit 

### Nouveau plan
- ajouter set_nonblock en switchless ocall
- en dessous de socket(), ajouter la fonction setsockopt
- ajouter ça dans handle connection until done: fd_set read_flags,write_flags; int sel; // the flag sets to be used
- voir si il y a le bind et le listen
- faire le switchless ocall à set_nonblock en dessous de accept :     set_nonblock(new_sd);

- dans le do-while : 
        FD_ZERO(&read_flags);
        FD_ZERO(&write_flags);
        FD_SET(new_sd, &read_flags);
        FD_SET(new_sd, &write_flags);
        FD_SET(STDIN_FILENO, &read_flags);
        FD_SET(STDIN_FILENO, &write_flags);
        sel = select(new_sd+1, &read_flags, &write_flags, (fd_set*)0, &waitd);
        if(sel < 0)
            continue;
        
-   if(FD_ISSET(new_sd, &read_flags)) {

    //clear set
    FD_CLR(new_sd, &read_flags);
    suivie de read_from_session_peer
    }

-   if(FD_ISSET(STDIN_FILENO, &read_flags))
        fgets(out, 255, stdin);


    //socket ready for writing
    if(FD_ISSET(new_sd, &write_flags)) {
        //printf("\nSocket ready for write");
        FD_CLR(new_sd, &write_flags);
        suivi de write_to_session_peer;
    }   //end if


### Re nouveau plan
- changer le noyau
- faire les accept au début et maintenir la connection
- 


### Resultat
- En changeant le noyau et en redistribuant les irqs sur le core 1, on arrive à avoir de manière consistantes 100 AEX par secondes. Sah c'est pas mal.

### Maintient des connexions
- Démarre tls_server
- lance handle_communication_until_done2
- 

- askTS
- launch_tls_client2
- initie contexte
- créer un socket client

- establish_connections --> init les connexions, met les sockets dans server_connections
- communicate_with_server --> envoie un message et attend une réponse 
- handle_connections --> créé les sets de FD à surveiller, fait le select, sur tout les servers auxquelles on est connecté, appel communicate_with_servers 


- askTS : 
    - set-up ctx
    - establish_connections
    - handle_connections  

Problème --> establish_connections n'est appelé qu'une fois, si le server n'est pas en ligne, le socket est fermé 
on peut retourner un tableau des servers auxquelles on est connecté, et dans handle connections, appeler à nouveau establish_connections sur ces indices

passer le contexte dans la structure globale
