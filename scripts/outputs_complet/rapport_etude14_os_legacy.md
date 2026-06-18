# Étude 14 — OS Legacy et Sécurité : Windows/Android = Moins Sécurisé ?
**Auteur :** Issakha Thiam  
**Généré le :** 2026-06-18 12:05:55

---
## 1. Questions de recherche

Les pays avec une forte prévalence de Windows ou Android adoptent-ils moins les protocoles modernes (TLS 1.3, IPv6, HTTP/3) ? Existe-t-il un 'effet OS' sur la sécurité internet ?

## 2. Méthodes

- Parts moyennes de chaque OS par pays sur 53 semaines
- Corrélations de Spearman entre parts OS et indicateurs de sécurité
- Régression linéaire Windows ~ TLS 1.3 (relation clé)

## 3. Matrice de corrélations Spearman

| OS | TLS 1.3 | IPv6 | HTTP/3 | BW médiane |
|-----|---------|------|--------|------------|
| WINDOWS | **0.150** | **0.320** | -0.081 | **0.473** |
| ANDROID | -0.095 | **-0.311** | 0.034 | **-0.577** |
| MACOSX | 0.100 | **0.246** | 0.067 | **0.599** |
| IOS | **-0.147** | 0.084 | **0.273** | **0.394** |
| LINUX | **0.156** | 0.052 | -0.046 | **0.454** |
| CHROMEOS | 0.059 | **0.129** | 0.053 | **0.203** |
| SMART_TV | **-0.179** | 0.004 | **0.334** | **0.310** |

*Gras = p<0.05*

## 4. Tendances mondiales

- **WINDOWS** : 3498.7% en moyenne  ↑
- **ANDROID** : 4007.5% en moyenne  ↓
- **MACOSX** : 704.8% en moyenne  ↑
- **IOS** : 1527.4% en moyenne  ↓
- **LINUX** : 170.5% en moyenne  ↑
- **CHROMEOS** : 54.3% en moyenne  ↑
- **SMART_TV** : 7.9% en moyenne  ↑

---
*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*