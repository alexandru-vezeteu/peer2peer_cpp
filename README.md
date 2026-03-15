# Sistem peer-to-peer pentru comunicare securizata si transfer de fisiere

Un sistem P2P descentralizat care permite comunicare end-to-end criptata, transfer de fisiere si autentificarea nodurilor, fara server central.

---

## Obiective

- Autentificarea nodurilor (fiecare nod are o identitate criptografica unica)
- Comunicare securizata si anonima intre utilizatori
- Transfer de fisiere prin retea distribuita
- Suport pentru mesaje offline (destinatarul nu trebuie sa fie online)

---

## Arhitectura sistemului

### 1. Identitate si autentificare (Ed25519)

Fiecare nod genereaza o pereche de chei **Ed25519** la prima pornire. Cheia publica defineste identitatea nodului:

```
NodeID = SHA-256(cheie_publica)
```

Orice mesaj trimis in retea este **semnat** cu cheia privata a expeditorului. Destinatarul verifica semnatura — daca nu verifica, mesajul e ignorat. Astfel, nimeni nu poate falsifica mesaje sau impersona alt nod.

### 2. Retea P2P — S/Kademlia DHT

La baza sistemului se afla un **DHT Kademlia** cu extensiile de securitate din **S/Kademlia**:

- **Puzzle static**: la generarea identitatii, `SHA-256(cheie_publica)` trebuie sa indeplineasca o conditie de dificultate (N biti de zero). Face generarea in masa de identitati false costisitoare.
- **Puzzle dinamic**: la fiecare reconectare in retea, nodul rezolva un proof-of-work cu TTL de 24h. Previne atacuri de tip join flooding.
- **Verificare NodeID**: orice contact primit prin retea e validat — `SHA-256(pubkey) == node_id`. Contactele false sunt aruncate imediat.
- **Disjoint lookups**: cautarile importante (FIND_VALUE) ruleaza pe 3 cai independente simultan. Rezultatul e acceptat doar daca cel putin 2 din 3 cai sunt de acord, protejand impotriva nodurilor malitioase.

DHT-ul suporta operatiile standard: `PING`, `FIND_NODE`, `STORE`, `FIND_VALUE`, cu replicare la k noduri si republica periodica pentru persistenta datelor.

### 3. Schimb de chei si sesiuni criptate (X25519 + ChaCha20-Poly1305)

La conectare, nodurile efectueaza un **handshake autentificat** inspirat din protocolul Noise XX:

1. Fiecare parte genereaza o pereche de chei efemere **X25519**
2. Schimba cheile publice efemere, semnate cu identitatea Ed25519
3. Calculeaza un shared secret prin ECDH
4. Deriva doua chei de sesiune (cate una per directie)

Toate mesajele ulterioare sunt criptate cu **ChaCha20-Poly1305** (AEAD) — cripteaza continutul si garanteaza integritatea. Un pachet modificat e detectat si aruncat.

### 4. Mesaje offline — X3DH

Daca destinatarul (Bob) este offline, mesajele sunt stocate in DHT cu un TTL. Pentru a permite criptarea fara ca Bob sa fie prezent, se foloseste protocolul **X3DH (Extended Triple Diffie-Hellman)**:

- Bob publica in DHT un **key bundle**: Identity Key + Signed PreKey + One-Time PreKeys (OPK)
- Alice descarca bundle-ul si calculeaza un shared secret folosind 4 operatii Diffie-Hellman
- Cripteaza mesajul si il stocheaza in DHT la adresa de mailbox a lui Bob
- Cand Bob revine online, calculeaza acelasi shared secret si decripteaza

OPK-urile sunt chei de unica folosinta ce asigura **forward secrecy** — chiar daca cheile pe termen lung sunt compromise ulterior, mesajele trecute raman in siguranta.

### 5. Forward secrecy per mesaj — Double Ratchet

Dupa stabilirea sesiunii prin X3DH, conversatia continua cu **Double Ratchet**. Fiecare mesaj foloseste o cheie derivata din cea anterioara (HKDF one-way). Compromiterea unui mesaj nu expune mesajele anterioare.

### 6. Transfer de fisiere — Content-Addressed Chunking

Fisierele sunt impartite in chunk-uri de 256 KB. Fiecare chunk e stocat in DHT la cheia `SHA-256(chunk_data)`. Un **manifest** descrie fisierul complet:

```
Manifest { filename, size, [hash_chunk_0, hash_chunk_1, ...] }
manifest_hash = SHA-256(manifest)
```

Expeditorul trimite destinatarului doar `manifest_hash`. Destinatarul il descarca din DHT, citeste lista de chunk hash-uri, descarca chunk-urile in paralel, verifica integritatea fiecaruia si reasambleaza fisierul.

---




## Stack tehnologic

| Componenta | Tehnologie |
|---|---|
| Limbaj | C++23 |
| Async I/O | Boost.Asio + coroutines |
| Serializare | Protocol Buffers |
| Criptografie | Implementare proprie (Ed25519, X25519, ChaCha20-Poly1305, SHA-256/512) |
| Build | Meson |

---

## Bibliografie

- [Kademlia: A Peer-to-peer Information System Based on the XOR Metric](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf)
- [S/Kademlia: A Practicable Approach Towards Secure Key-Based Routing](https://www.tm.uka.de/doc/SKademlia_2007.pdf)
- [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [RFC 8032 — Edwards-Curve Digital Signature Algorithm (Ed25519)](https://tools.ietf.org/html/rfc8032)
- [RFC 7748 — Elliptic Curves for Diffie-Hellman Key Agreement (X25519)](https://tools.ietf.org/html/rfc7748)
- [RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439)
- [Tor: The Second-Generation Onion Router](https://svn.torproject.org/svn/projects/design-paper/tor-design.pdf)