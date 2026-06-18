# Étude 13 — Trafic Bot vs Vulnérabilité : les Pays Vulnérables Attirent-ils Plus de Bots ?
**Auteur :** Issakha Thiam  
**Généré le :** 2026-06-18 12:02:33

---
## 1. Questions de recherche

Les pays avec de faibles indicateurs de sécurité (TLS 1.3 bas, peu d'IPv6, peu d'HTTP/3, faible bande passante) sont-ils davantage exposés au trafic bot ? Le trafic bot est-il corrélé à la vulnérabilité structurelle ?

## 2. Méthodes

- Ratio bot = traffic bot / (humain + bot) par pays, moyenne sur 53 semaines
- Corrélations de Spearman (non paramétriques, robustes aux outliers)
- Séries temporelles du ratio mondial

## 3. Résultats

| Indicateur | ρ Spearman | p-value | Interprétation |
|------------|-----------|---------|----------------|
| TLS 1.3 (%) | 0.337 | 0.0000 | plus de bots si sécurité ↑ |
| IPv6 (%) | 0.066 | 0.3003 | plus de bots si sécurité ↑ |
| HTTP/3 (%) | -0.615 | 0.0000 | moins de bots si sécurité ↑ |
| Bande passante médiane | 0.069 | 0.2848 | plus de bots si sécurité ↑ |

## 4. Statistiques globales

- Ratio bot mondial moyen : **20.5%**
- Ratio bot max : **24.3%** | min : **16.7%**
- Pays avec ratio bot le plus élevé : **GI** (90.7%)

---
*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*