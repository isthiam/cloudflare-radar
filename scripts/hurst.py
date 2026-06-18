import pandas as pd
import numpy as np

df = pd.read_csv("E:\\Webscraping\\cloudflare_radar_vulnerabilite\\data\\radar_api_donnees_brutes_daily.csv", parse_dates=["date"])
df = df.sort_values("date")

# Série IPv6 (%)
x = df["attack_ipv6_pct"].astype(float)

# Incréments (objet math du modèle)
dx = x.diff().dropna().values

print("Nombre d'observations utilisables :", len(dx))


def hill_alpha(x, k=None):
    x = np.abs(x)
    x = x[x > 0]
    x = np.sort(x)[::-1]

    if k is None:
        k = int(np.sqrt(len(x)))
        k = max(20, min(k, len(x)//5))

    yk1 = x[k]
    gamma = np.mean(np.log(x[:k]) - np.log(yk1))
    return 1 / gamma

alpha_hat = hill_alpha(dx)
print("alpha estimé =", round(alpha_hat, 3))


def p_variation(x, n, p, r=0):
    N = 2 ** n
    lag = 2 ** r
    x = x[:N+1]
    inc = x[lag:] - x[:-lag]
    return np.mean(np.abs(inc) ** p)

def estimate_H(dx, p, r=1, n_min=5, n_max=8):
    H_vals = []
    for n in range(n_min, n_max + 1):
        V0 = p_variation(dx, n, p, r=0)
        Vr = p_variation(dx, n, p, r=r)
        H = (1 / (r * p)) * np.log2(Vr / V0)
        H_vals.append((n, H))
    return pd.DataFrame(H_vals, columns=["n", "H"])


p = min(1.0, 0.8 * alpha_hat)
results = estimate_H(dx, p=p)

print(results)
print("H final (médiane) =", round(results["H"].median(), 3))
