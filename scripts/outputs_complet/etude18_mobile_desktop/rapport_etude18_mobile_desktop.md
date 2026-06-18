# Étude 18 — Fracture Mobile/Desktop : les Utilisateurs Mobiles Sont-ils Moins Bien Protégés ?
**Auteur :** Issakha Thiam  
**Généré le :** 2026-06-18 12:12:24

---
## 1. Questions de recherche

Les pays avec une forte proportion d'utilisateurs mobiles adoptent-ils moins les protocoles modernes (TLS 1.3, IPv6, HTTP/3) ? La 'mobilisation' du trafic est-elle associée à une moindre sécurité ou, au contraire, à une adoption accélérée via les navigateurs mobiles ?

## 2. Méthodes

- Part mobile = mobile / (desktop + mobile + other) par pays, moyenne 53 semaines
- Corrélations de Spearman entre part mobile et indicateurs de sécurité
- Tests Kruskal-Wallis entre tertiles de part mobile

## 3. Corrélations clés

| Indicateur | ρ Spearman | p-value | Interprétation |
|------------|-----------|---------|----------------|
| TLS 1.3 | -0.140 | 0.0277 | mobile → moins sécurisé |
| IPv6 | -0.261 | 0.0000 | mobile → moins sécurisé |
| HTTP/3 | 0.160 | 0.0120 | mobile → plus sécurisé |
| BW médiane | -0.531 | 0.0000 | mobile → moins sécurisé |
| Ratio bot | -0.425 | 0.0000 | mobile → moins sécurisé |

## 4. Tests Kruskal-Wallis (tertiles mobile)

| Indicateur | H | p-value |
|------------|---|---------|
| TLS 1.3 | 17.621 | 0.0001 |
| IPv6 | 18.123 | 0.0001 |
| HTTP/3 | 23.347 | 0.0000 |
| BW médiane | 64.300 | 0.0000 |
| Ratio bot | 53.349 | 0.0000 |

## 5. Part mobile mondiale

- Moyenne : **48.9%**
- Tendance : ↓ baisse

---
*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*