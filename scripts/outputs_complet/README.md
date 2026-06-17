# Téléchargement Cloudflare Radar — Récapitulatif

**Date :** 09 juin 2026  
**Auteur :** Issakha Thiam  
**Script :** `radar_complet_download.py`

---

## Fichiers générés (25 CSV)

| Section | Fichier | Lignes | Paramètres |
|---------|---------|--------|------------|
| **A. HTTP par pays** | `http/http_ip_version.csv` | 13 409 | 52w, 1w, 253 pays |
| | `http/http_tls_version.csv` | 13 409 | |
| | `http/http_http_version.csv` | 13 409 | |
| | `http/http_device_type.csv` | 13 409 | |
| | `http/http_bot_class.csv` | 13 409 | |
| | `http/http_os.csv` | 13 409 | |
| | `http/http_browser_family.csv` | 13 409 | |
| **B. Attaques L7 globales** | `attacks_l7/attacks_l7_vertical.csv` | 85 | 12w, 1d |
| | `attacks_l7/attacks_l7_http_method.csv` | 85 | |
| | `attacks_l7/attacks_l7_http_version.csv` | 85 | |
| **C. Attaques L3 globales** | `attacks_l3/attacks_l3_protocol.csv` | 53 | 52w, 1w |
| | `attacks_l3/attacks_l3_bitrate.csv` | 53 | |
| | `attacks_l3/attacks_l3_ip_version.csv` | 53 | |
| **D. IQI par pays** | `iqi/iqi_bandwidth.csv` | 13 409 | 52w, 1w, 253 pays |
| | `iqi/iqi_dns.csv` | 13 409 | |
| **E. BGP global** | `bgp/bgp_timeseries.csv` | 53 | 52w, 1w |
| | `bgp/bgp_hijacks.csv` | 20 000 | 52w, pagination (cap 200 pages) |
| | `bgp/bgp_leaks.csv` | 20 000 | 52w, pagination (cap 200 pages) |
| **F. Email Security globale** | `email/email_dmarc.csv` | 53 | 52w, 1w |
| | `email/email_dkim.csv` | 53 | |
| | `email/email_spf.csv` | 53 | |
| | `email/email_malicious.csv` | 53 | |
| | `email/email_spam.csv` | 53 | |
| | `email/email_spoof.csv` | 53 | |
| **G. DNS global** | `dns/dns_timeseries.csv` | 52 | 52w, 1w |

**Total : 25 fichiers CSV**

---

## Contraintes API Cloudflare Radar v4 (leçons apprises)

| Endpoint | aggInterval max | dateRange max | Notes |
|----------|----------------|---------------|-------|
| HTTP timeseries_groups (par pays) | `1w` | `52w` | Pas de `name=main`, pas de `dateStart/dateEnd` |
| L7 attacks timeseries_groups | `1d` | `12w` | Ne supporte PAS `aggInterval=1w` (500) ; `>12w` → 400 |
| L3 attacks timeseries_groups | `1w` | `52w` | Global uniquement, pas de `location` |
| IQI timeseries_groups (par pays) | `1w` | `52w` | Avec `location` |
| BGP timeseries | `1w` | `52w` | |
| BGP events (hijacks/leaks) | — | `52w` | Pagination 100 evt/page, cap 200 pages |
| Email Security timeseries_groups | `1w` | `52w` | |
| DNS timeseries | `1w` | `52w` | |

**Réponse standard :** `result.serie_0.timestamps` + clés valeurs (pas `result.main`)

---

## Structure des colonnes principales

- **Séries HTTP/L3/L7/Email/DNS :** `date`, `country_iso2` (si par pays), colonnes de pourcentage par catégorie
- **IQI :** `date`, `country_iso2`, `metric`, valeurs de qualité
- **BGP timeseries :** `date`, valeurs
- **BGP events :** colonnes événement aplaties (id, date, type, ASN impliqués, etc.)
