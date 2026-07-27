# RXC: prelazak na PoS + čišćenje masternode liste

Radni dizajn dokument. Status: **prijedlog za odobrenje**, ništa još nije implementirano.

---

## 1. Odluke (dogovoreno)

| Parametar | Vrijednost |
|---|---|
| Stake prag | **10.000 RXC** |
| Stake maturity | 8h (coin mora odstajati prije stakeanja) |
| MN kolateral | **10.000 RXC** (podignuto s 1.000) |
| Podjela nagrade | **MN 70% / staker 30%** |
| Nagrada po bloku | ostaje kakva jeste |
| Prelazni period | **2-3 mjeseca** hibrid PoW+PoS, pa gašenje PoW-a |

Trenutna emisija (provjereno u kodu, `validation.cpp:1138`):
`nSubsidyBase = 50` → halving na 210.000 (prošao, sad smo na ~324.800) → **25 RXC**,
minus 10% za superblock/budžet → **22,5 RXC ide u blok**, 2,5 u budžet.

Poslije forka: 22,5 → **15,75 masternodeu** + **6,75 stakeru**.

---

## 2. ⚠️ ZLATNO PRAVILO: sve mora biti height-gated

Ovo je ista zamka koja je već jednom slomila sync (`llmq50_60` 50→5 → `bad-qc-invalid-null`).

**Svaka promjena konsenzusnog parametra mora važiti tek od visine H nadalje.**
Ako se promijeni globalno, node ne može validirati vlastitu istoriju i ne prolazi sync.

Konkretno, ovo su mine u kodu:

### 2.1 Kolateral — 4 mjesta, sva validiraju i STARE blokove
```
src/evo/providertx.cpp:140     coin.out.nValue != 1000 * COIN
src/evo/providertx.cpp:159     tx.vout[...].nValue != 1000 * COIN
src/evo/deterministicmns.cpp:640
src/evo/deterministicmns.cpp:920
```
Ako se `1000` samo prepiše u `10000`, **svaka istorijska ProRegTx postaje nevalidna** → node ne može proći kroz lanac.

Rješenje — helper s visinom:
```cpp
CAmount GetMNCollateral(int nHeight) {
    return nHeight >= Params().GetConsensus().nPoSForkHeight
        ? 10000 * COIN
        : 1000 * COIN;
}
```
i sva 4 mjesta idu kroz njega.

### 2.2 Podjela nagrade — sreća, plumbing već postoji
```cpp
// src/validation.cpp:1162  (trenutno)
CAmount GetMasternodePayment(int nHeight, CAmount blockValue) {
    CAmount ret = blockValue * 0.5;   // 50/50 rudar/MN
    return ret;
}
```
Funkcija **već prima `nHeight`** → height-gate je trivijalan i siguran:
```cpp
CAmount GetMasternodePayment(int nHeight, CAmount blockValue) {
    if (nHeight >= Params().GetConsensus().nPoSForkHeight)
        return blockValue * 0.7;      // 70% masternodeu
    return blockValue * 0.5;          // istorija ostaje netaknuta
}
```

### 2.3 LLMQ parametri
Ostaju **nedirnuti** do H. Poslije čišćenja liste (vidi 3.2) razmatramo manje kvorume —
ali tek kad vidimo koliko se stvarnih nodeova diglo.

---

## 3. Faze

### H = visina forka (PoS start)
Sve u istom bloku, jedan koordinirani upgrade:

1. **PoS aktivan** — blokovi se mogu praviti i stakeanjem (coinstake), PoW i dalje radi
2. **Reset MN liste** — svi postojeći MN-ovi se poništavaju
   - Živi se vraćaju s `ProUpServTx` / novom registracijom (mehanizam već postoji:
     `deterministicmns.cpp:702-706` postavlja `nPoSeBanHeight = -1`)
   - Novi kolateral (10.000) važi za sve registracije od H nadalje
3. **Nova podjela** 70/30 stupa na snagu

**Napomena o kolateralima duhova:** oni NISU zaključani protokolom.
U DIP3 se MN briše iz liste čim vlasnik potroši kolateral UTXO — znači tih 1.000 RXC
ljudi mogu potrošiti kad hoće. Problem je bio samo što ih PoSe nikad nije izbacio.

### H2 = gašenje PoW-a (H + 2-3 mjeseca)
- Od H2 blokovi smiju biti isključivo PoS
- `CheckProofOfWork` (`pow.cpp:229`, pozivi u `validation.cpp:1097` i `:3221`)
  se od H2 preskače za nove blokove, ali **mora ostati aktivan za sve blokove < H2**

**Preporuka:** H2 kontrolisati **sporkom** umjesto fiksne visine.
Tako se PoW gasi tek kad se stvarno vidi da staking radi i da ima dovoljno nodeova —
bez potrebe za novim hard forkom ako nešto krene po zlu.
*(Otvoreno pitanje: ko drži spork ključ — vidi sekciju 6.)*

---

## 4. Najveći dio posla: PoS konsenzus

Dash 0.14 nema **nijednu liniju** PoS-a. Ovo se piše/portuje:

| Komponenta | Šta je |
|---|---|
| Coinstake transakcija | poseban tip tx kojim staker uzima nagradu |
| Kernel hash + stake modifier | "lutrija" — ko smije napraviti blok |
| Potpis bloka | PoS blok potpisuje staker svojim ključem |
| Stake weight / maturity | 10.000 RXC prag, 8h odstajanja |
| Difficulty za PoS | odvojen retarget od PoW-a |
| Wallet staking petlja | proces koji pokušava stakeati |
| Zaštite | nothing-at-stake, stake grinding |

**Referenca:** PIVX — Dash fork koji je prošao tačno ovaj put i **zadržao masternodeove**.
To je najbliži uzor; ne izmišljamo iz nule.

---

## 5. Plan testiranja (obavezno, ovim redom)

1. **Grana, ne master.** Sve na `feature/pos`.
2. **Regtest** — PoS radi u izolaciji, blokovi se prave stakeanjem.
3. **Testnet s lažnim H** — postaviti H na malu visinu, proći cijeli ciklus:
   PoW → hibrid → MN reset → PoS-only.
4. **Sync cijelog mainnet lanca s novim binarijem** — od genesisa do vrha.
   Ovo je test koji hvata height-gating greške. **Ako ovo ne prođe, ne ide dalje.**
5. **Tek onda** mainnet: prvo pool i explorer daemon, pa objava zajednici s rokom.

---

## 6. Otvorena pitanja

1. **Spork ključ** — `SetSporkAddress` (`spork.cpp:334`) se poziva iz `init.cpp`.
   Treba potvrditi imaš li privatni ključ za mainnet spork adresu. Ako imaš,
   H2 ide preko sporka (sigurnije). Ako nemaš, mora fiksna visina.
2. **Visine H i H2** — konkretni brojevi, tek kad znamo datum objave.
3. **Da li MN-ovi zadržavaju InstantSend/ChainLocks** — ako da, poslije reseta
   treba i smanjenje kvoruma (5/3) da DKG uopšte prolazi s malim brojem nodeova.

---

## 7. Ono što treba riješiti PRIJE forka

Lanac trenutno **stoji kad ne kopaš** (zadnji blok bio prije ~6h kad je rig bio ugašen).
Do forka mreži treba neko ko kontinuirano kopa, inače nema ni blokova u kojima bi fork
uopšte aktivirao.
