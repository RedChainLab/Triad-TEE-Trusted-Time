# Notes sur le comportement du server

- Lors de l'initialisation tout va bien, les deux clients/Servers communiquent entre eux
- Si un des clients est interrompue, je vois pas d'erreur particulière sur l'autre
- Reconnection du node interrompue --> la plupart du temps, le SSL_connect n'aboutie pas

Il me faut un client qui peut faire des demandes de TS --> OK
ré-implémenter la logique d'obtention de TS --> OK

rajouter la connection au trusted server
Il faut que je rajoute la calibration et la connection au server trusted 

## Nettoyage
- je devrais pouvoir supprimer des trucs dans common, calibration
- faire un README pour tout expliquer et un script pour tout lancer
