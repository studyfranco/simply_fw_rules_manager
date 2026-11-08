# Audit Technique & Analyse d'Impacts des Scripts `scripts_etc/firewall*`

Ce document présente l'analyse détaillée des scripts existants ([`scripts_etc/firewall`](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/scripts_etc/firewall), [`scripts_etc/firewall.tools`](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/scripts_etc/firewall.tools) et [`scripts_etc/firewall.set.ip`](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/scripts_etc/firewall.set.ip)), en expliquant pour chaque point :
1. **Le constat exact** (fichier et numéros de lignes),
2. **La cause racine technique**,
3. **L'évaluation précise des impacts Avant / Après correction**.

---

## 1. Bugs fonctionnels avérés (Règles ignorées ou doublons)

### 1.1 Casse de variable incohérente dans `insert_docker_inter_forward_main`
- **Localisation :** [`scripts_etc/firewall` (lignes 1212–1213)](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/scripts_etc/firewall#L1212-L1213)
- **Code actuel :**
  ```bash
  local network_interface=$(get_bridge_name_docker_network "${dnatPORTC[1]}")
  if [ -n "${NetworkInterface}" ]; then
      insert_rules_with_test_ok_ipv4 "filter -I ${CHAINFORWARDDOCKER} ! -i ${network_interface} -o ${network_interface} ..."
  ```
- **Cause racine :** La variable locale est assignée en `snake_case` (`network_interface`), mais le test conditionnel ligne 1213 vérifie `${NetworkInterface}` en `PascalCase`. Bash étant sensible à la casse, `${NetworkInterface}` est vide (sauf fuite accidentelle d'une variable globale d'une fonction appelante).
- **Impact Avant :** La fonction `insert_docker_inter_forward_main` n'insère **aucune** règle `CHAINFORWARDDOCKER` pour les ports `openDockerTCP/UDP`, `WWDockerTCP/UDP`, `internalDockerTCP/UDP`, `localDockerTCP/UDP` et `IPAutorDockerTCP/UDP`.
- **Impact Après (`if [ -n "${network_interface}" ]; then`) :** Les règles de transfert inter-interfaces vers le bridge Docker cible sont effectivement créées comme prévu par l'architecture.

---

### 1.2 Variable `$NETWORK` non définie dans `insert_rules_list_docker_forward`
- **Localisation :** [`scripts_etc/firewall` (lignes 1181–1182)](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/scripts_etc/firewall#L1181-L1182)
- **Code actuel :**
  ```bash
  IFS=':' read -r -a containerDNATC <<< "$containerDNAT"
  local json_NETWORK=$(${DOCKER} network inspect -f '{{json .IPAM.Config}}' "${NETWORK}")
  ```
- **Cause racine :** Le réseau cible est stocké dans `${containerDNATC[1]}`, mais la commande inspecte `"${NETWORK}"` qui n'est pas défini dans cette portée (et le résultat `json_NETWORK` n'est d'ailleurs jamais utilisé).
- **Impact Avant :** À chaque règle DNAT Docker, un processus `docker network inspect ""` est lancé inutilement et échoue avec un code retour non nul, ralentissant le démarrage du firewall.
- **Impact Après :** Suppression de l'appel mort ou utilisation de `${containerDNATC[1]}` si nécessaire, éliminant un appel CLI Docker en échec par règle.

---

### 1.3 Mauvaise variable (`$IPSLISTGOODIP` au lieu de `$IP`) et `sed -i` concurrents dans `add_ipaut`
- **Localisation :** [`scripts_etc/firewall.set.ip` (lignes 93–108)](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/scripts_etc/firewall.set.ip#L93-L108)
- **Code actuel :**
  ```bash
  for IP in "${IPAutor[@]}"
  do
      if [[ $IP =~ .*:.* ]]; then
          $IPS add "${IPSLISTGOODIP}6" $IP -exist &
      else
          $IPS add $IPSLISTGOODIP $IP -exist &
      fi
      $ROUTE -n del $IPSLISTGOODIP reject &>/dev/null &
      $SED -i "/^ALL: ${IPSLISTGOODIP} : DENY/d" "${hosts_deny_file}" &
  done
  ```
- **Cause racine :**
  1. Les lignes 104 et 105 utilisent `$IPSLISTGOODIP` (qui vaut littéralement la chaîne `"good_ip"`) au lieu de `$IP` !
  2. La commande `sed -i ... &` est lancée en arrière-plan dans une boucle sur le même fichier `/etc/hosts.deny`. Or `sed -i` crée un fichier temporaire puis le renomme (`rename(2)`) vers `/etc/hosts.deny` : plusieurs `sed -i` concurrents s'écrasent mutuellement ou échouent.
- **Impact Avant :** Une IP présente dans `IPAutor` qui aurait été précédemment bannie dans `route reject` ou `/etc/hosts.deny` n'est **jamais** débannie (le script essaie de supprimer la route `"good_ip"`), et `/etc/hosts.deny` subit une condition de course.
- **Impact Après :** Remplacement par `$IP` et exécution séquentielle (ou regroupée en une seule passe `sed`) sur `/etc/hosts.deny`.

---

### 1.4 Utilisation de `$IPT` (IPv4) au lieu de `$IPT6` (IPv6) avec un `ipset` IPv6
- **Localisation :** [`scripts_etc/firewall` (ligne 1718)](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/scripts_etc/firewall#L1718)
- **Code actuel :**
  ```bash
  elif [ ! -z "${INTERC[2]}" ]; then
      if ! $IPT -t nat -C ${chaintouse} -m set --match-set ${IPSLISTBADIP}6 src -j RETURN &>/dev/null; then
          insert_rules_with_test_ok_ipv6 "nat -I ${chaintouse} 1 -m set --match-set ${IPSLISTBADIP}6 src -j RETURN"
      fi
  ```
- **Cause racine :** Le test `-C` (check) appelle `$IPT` (`iptables` IPv4) en lui passant l'ensemble IPv6 `${IPSLISTBADIP}6`. `iptables` IPv4 échoue systématiquement à reconnaître un `ipset` de famille `inet6`.
- **Impact Avant :** Le test `if ! $IPT ... -C` est toujours vrai, ce qui réinsère la règle en doublon en tête de chaîne (`-I ... 1`) à chaque rechargement.
- **Impact Après (`if ! $IPT6 -t nat -C ...`) :** La détection d'existence fonctionne en IPv6 et garantit l'idempotence.

---

### 1.5 Inversion `-d` (destination) vs `-s` (source) dans `delete_rules()` pour le Multicast/Broadcast
- **Localisation :** [`scripts_etc/firewall` (lignes 91 vs 672–673)](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/scripts_etc/firewall#L91)
- **Constat :** `set_rules()` insère `-d 224.0.0.0/24 -j RETURN` et `-d 255.255.255.255 -j RETURN` dans `${CHAINCHECKSPOOF}`, tandis que `delete_rules()` tente de supprimer `-s 224.0.0.0/24` et `-s 255.255.255.255`.
- **Impact Avant :** Lors d'un `stop` ou `delete_rules`, ces deux règles ne sont pas supprimées proprement avant le flush.
- **Impact Après :** Alignement sur `-d` dans `delete_rules()`.

---

### 1.6 Tableau `pidsb` orphelin dans `flush_rules()` et `&& \` manquant dans `set_rules()`
- **Localisation :** [`scripts_etc/firewall` (lignes 376, 826–827, 917–918)](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/scripts_etc/firewall#L826-L827)
- **Constat :**
  - Dans `flush_rules()`, quatre commandes `iptables -t raw -F` ajoutent leur PID à `pidsb+=($!)` alors que la barrière de synchronisation finale fait `wait "${pids[@]}"`.
  - Ligne 376, `insert_docker_inter_forward_main "${openDockerUDP[@]}" "udp"` n'a pas le `&& \` de continuation de chaîne présent sur son homologue TCP ligne 302, ce qui interrompt prématurément la chaîne `&&` de `set_rules()` et exécute la suite hors du bloc conditionnel.
- **Impact Après :** Synchronisation complète des PIDs lors du flush et chaîne `&&` intègre dans `set_rules()`.

---

## 2. Architecture, Performance & Fiabilité (Verrou `xtables` et Docker CLI)

### 2.1 Contention massive sur le verrou `/run/xtables.lock` (Parallélisme `&` sans `-w`)
- **Constat (visible dans [`example/MainServ/firewall.log`](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/example/MainServ/firewall.log)) :**
  Le script lance des centaines d'appels `$IPT` et `$IPT6` en arrière-plan (`&`) simultanément sans le flag `-w` (`--wait`). Dans le noyau Linux, la mise à jour d'une table `xtables` prend un verrou exclusif. Lorsque 50 processus `iptables` s'exécutent en parallèle sans `-w`, 49 échouent immédiatement avec `Another app is currently holding the xtables lock`.
  Pour compenser, `insert_rules_with_test_ok_ipv4` boucle jusqu'à 10 fois avec un `sleep 1` et affiche `"Bugged v4 ..."`.
- **Impact Avant :**
  - Temps d'exécution de 15 à 45 secondes à cause des `sleep 1` de retry.
  - Risque qu'une règle échoue ses 10 tentatives lors d'un pic de charge et soit silencieusement absente du pare-feu actif.
- **Impact Après :**
  1. **Court terme (0 changement d'architecture) :** Ajout systématique de `-w 5` aux appels `iptables`/`ip6tables`, ce qui fait attendre chaque binaire proprement en C sur le verrou fichier au lieu d'échouer et de faire un `sleep 1` en Bash.
  2. **Moyen terme :** Utilisation de `ipset restore -! < file` (déjà partiellement utilisé dans `firewall.set.ip`) et possibilité d'utiliser `iptables-restore --noflush` pour appliquer un lot de règles en une seule transaction noyau atomique (< 50 ms).

---

### 2.2 Appels redondants à `${DOCKER} container inspect` et `network inspect` dans les boucles
- **Constat :**
  Sur `MainServ`, `dockerAccessBetweenThem` contient **plus de 130 règles**. Pour chacune d'elles, `insert_rules_list_docker_ports_to_another_container` appelle :
  - `get_ip_docker_network` (conteneur source) → `docker container inspect`
  - `get_ip6_docker_network` (conteneur source) → `docker container inspect`
  - `get_ip_docker_network` (conteneur destination) → `docker container inspect`
  - `get_ip6_docker_network` (conteneur destination) → `docker container inspect`
  - `get_bridge_name_docker_network` (réseau) → `docker network inspect`
  Soit **plus de 650 invocations du client CLI Docker** pour les seules règles inter-conteneurs, alors que les mêmes conteneurs (`traefik_tomidejetsu`, `socket-proxy`, `unbound`, `postgres_nextcloud`, etc.) reviennent des dizaines de fois !
- **Impact Avant :** Plusieurs secondes passées uniquement à forker le binaire `/usr/bin/docker` et sérialiser du JSON auprès du démon Docker.
- **Impact Après (dans `firewall.tools`) :**
  Mise en cache mémoire dans des tableaux associatifs Bash (`declare -gA _FW_CACHE_CONTAINER_IPV4`, `_FW_CACHE_CONTAINER_IPV6`, `_FW_CACHE_NET_BRIDGE`) dans `firewall.tools`. Chaque couple `(conteneur, réseau)` n'est inspecté **qu'une seule fois** par exécution du script : le nombre d'appels `docker inspect` chute de ~650 à ~35 (un par conteneur unique), divisant par ~10 le temps de chargement des règles Docker.

---

### 2.3 Duplication de fonctions entre `scripts_etc/firewall` et `scripts_etc/firewall.tools`
- **Constat :**
  `scripts_etc/firewall` source `/etc/init.d/firewall.tools` à la ligne 15, mais redéfinit ensuite en son sein `insert_rules`, `insert_rules_quietly`, `insert_rules_with_test_ok`, `insert_rules_with_test_ok_ipv4`, `insert_rules_with_test_ok_ipv6` et `insert_rules_list_ports`.
- **Impact Avant :** Risque de divergence de comportement selon qu'une fonction est appelée avant ou après la redéfinition, et maintenance en double.
- **Impact Après :** Centralisation unique des primitives d'insertion et des nouveaux helpers Docker génériques dans `firewall.tools`.
