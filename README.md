# Knight-WiFiArea

Portail captif Wi-Fi local pour Windows : Windows Hotspot / ICS fournit le réseau client, WinDivert (`pydivert`) filtre et comptabilise le trafic, et Flask avec SQLite gère le portail, les tickets et les quotas.

## Configuration

1. Copiez `.env.example` vers `.env`, puis définissez un mot de passe admin robuste, une clé Flask aléatoire et le domaine local souhaité. Le fichier `.env` est chargé au démarrage.
2. Les valeurs de repli du mot de passe et de la clé de session sont visibles en haut de `app.py` (section `CONFIGUREZ VOS PARAMÈTRES ICI`).
3. Le domaine DNS est lu depuis `CUSTOM_DOMAIN` ; les paramètres réseau `HOTSPOT_SUBNET` et `GATEWAY_IP` ainsi que la détection du domaine sont regroupés en haut de `firewall_engine.py` (`CONFIGUREZ VOTRE DOMAINE LOCAL ICI`). Le sous-réseau est configuré comme un préfixe IPv4 terminé par un point. Le QR code admin et l’URL affichée au démarrage utilisent le domaine configuré.
4. Les tarifs et leur calcul sont définis dans `templates/login.html`, dans la fonction JavaScript `updatePrice()`.

## Installation et lancement

Activez Windows Hotspot / ICS, puis ouvrez PowerShell **en tant qu’Administrateur** dans le dossier du projet :

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
# Modifiez .env avec vos propres valeurs avant de démarrer.
python app.py
```

Le portail écoute sur le port 80 et initialise `wifizone.db` au démarrage. WinDivert et l’écoute réseau nécessitent les droits Administrateur.
