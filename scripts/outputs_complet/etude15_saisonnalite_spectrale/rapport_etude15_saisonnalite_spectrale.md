# Étude 15 — Saisonnalité Spectrale des Indicateurs Internet Mondiaux
**Auteur :** Issakha Thiam  
**Généré le :** 2026-06-18 12:07:45

---
## 1. Questions de recherche

Existe-t-il des cycles réguliers (hebdomadaires, mensuels, trimestriels) dans les indicateurs de sécurité internet ? Le trafic bot, les attaques L3, ou le spam présentent-ils une saisonnalité structurelle ?

## 2. Méthodes

- **FFT (Transformée de Fourier rapide)** : décomposition spectrale des séries temporelles mondiales
- **Moyenne mobile MA(4)** : extraction de la tendance (équivalent décomposition additive)
- Résidus = série originale − tendance (composante saisonnière + bruit)

## 3. Périodes dominantes

| Indicateur | Période dominante (sem) | Amplitude |
|------------|------------------------|-----------|
| TLS 1.3 (%) | 53.0 | 3493.40 |
| IPv6 (%) | 53.0 | 2787.53 |
| HTTP/3 (%) | 53.0 | 2128.00 |
| BW médiane | 53.0 | 48.65 |
| Ratio bot (%) | 53.0 | 46.95 |
| BGP routes | 13.2 | 52834659561.70 |
| Spam (%) | 53.0 | 2573.20 |

## 4. Interprétation

- Une période de **4 semaines** indique un cycle mensuel
- Une période de **13 semaines** correspond à un cycle trimestriel
- Une période de **26 semaines** suggère une saisonnalité semi-annuelle


---
*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*