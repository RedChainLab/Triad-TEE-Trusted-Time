# Infos sur la compilation 

## Ordre de compilation, ajout d'un dossier common

### Début de la compilation de App

```Makefile
App/Enclave_u.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path $(SGX_SDK)/include 
	@echo "rule 1, App/Enclave_u.h"
	@echo "GEN  =>  $@"
```

la cible est Enclave_u.h, on commence par appeler `SGX_EDGER8R` pour lui dire qu'il va devoir compiler du code untrusted (d'après le fichier .edl). On ajoute les dossiers où il devra chercher
la ligne de compilation est une règle implicite de makefile

```Makefile
Common/ucommon.o: Common/ucommon.cpp App/Enclave_u.h
	@echo "rule 2, $@"
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $^"
```

La cible est ucommon.o, elle est compilée normalement, le fichier ucommon.cpp doit inclure `#include "../App/Enclave_u.h"`, de la même manière que l'on inclut ce header dans `app.cpp`

```Makefile
$(App_Name): App/Enclave_u.o $(App_Cpp_Objects) Common/ucommon.o
	@echo "target : $@"
	@echo "prereq : $^"
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"
```

A la fin, on ajoute le fichier objet `ucommon.o` à la compilation de app 


## A tester
- Créer 2 t_worker
- un compte les ADD
- l'autre attend 2s et passe un bool à true (sinon false)

# Result
without setting the affinity in the program directly and without taskset and without redireicting IRQs
--> 500 in 5 sec

setting core affinity in program only
--> to core 0 : 500 in 5 sec
--> to core 1 : 2600 in 5 sec
--> to core 2 : 500 in 5 sec
--> to core 3 : 510 in 5 sec

en observant les core asssociés avec chaque processus, on constate que le core est correctement assigné

setting core affinity with taskset only
--> to core 0 : < 5 ?
--> to core 1 : < 5
--> to core 0 and 1 : 500

watch -n 1 'ps -e -o pid,psr,comm | awk '\''$2 == "0" || $2 == "1" && $1 > "9000" '\''' --> permet de surveiller quel programme run sur CPU0
watch -n 1 'ps -e -o pid,psr,comm | awk '\''$2 < 4  && $1 > 9000 '\'''

## Observation 
- on voit effectivement le process sur un coeur cohérent, par exemple avec la commande taskset 1 ./app, on voit le processus app sur le core 0
- on ne voit pas le processus sur différent core, par exemplen taskset 3 ./app devrait faire tourner le processus sur le core 0 et 1 (3 = 0b11), pourtant le nombre de AEX compté est au alentours de 500
- si on spécifie plus de 2 core, par exemple taskset 5, le nombre peut exploser mais c'est random

Il semblerait que taskset réduit le nombre de AEX quand 1 seul core est assigné, il faudrait regarder la différence entre tasket et set_affinity()
RAS si les taskset et set_affinity sont utilisés en même temps.

Vérifions que les AEX sont vraiment comtpé correctement

essayons de rajouter les add pour voir quand interviennent les AEX

avec les add --> je sais pas quand sont compté les quelques aex, pas dans le tableau de add