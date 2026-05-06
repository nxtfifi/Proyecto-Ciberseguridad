import requests

RUTAS_SENSIBLES = [
    "/robots.txt", "/.env", "/admin", "/administrator", "/login", "/wp-admin",
    "/backup", "/config", "/phpinfo.php", "/server-status", "/.git/HEAD",
    "/api", "/swagger", "/api-docs", "/.htaccess", "/web.config",
]

def check_exposure(url: str) -> dict:
    result = {"expuesto": [], "no_encontrado": [], "error": None}
    base = url.rstrip("/")
    try:
        for ruta in RUTAS_SENSIBLES:
            try:
                r = requests.get(base + ruta, timeout=5, allow_redirects=False)
                if r.status_code in (200, 301, 302, 403):
                    result["expuesto"].append({
                        "ruta": ruta,
                        "status": r.status_code,
                        "riesgo": "Alto" if r.status_code == 200 else "Medio",
                    })
                else:
                    result["no_encontrado"].append(ruta)
            except Exception:
                result["no_encontrado"].append(ruta)
    except Exception as e:
        result["error"] = str(e)
    return result
