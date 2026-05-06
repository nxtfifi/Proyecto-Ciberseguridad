import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protege contra ataques MITM forzando HTTPS",
    "Content-Security-Policy": "Previene XSS controlando recursos que puede cargar el sitio",
    "X-Frame-Options": "Previene clickjacking bloqueando iframes no autorizados",
    "X-Content-Type-Options": "Evita que el navegador adivine el tipo de contenido",
    "Referrer-Policy": "Controla qué información de referencia se comparte",
    "Permissions-Policy": "Controla acceso a funciones del navegador (cámara, micrófono, etc.)",
    "X-XSS-Protection": "Activa el filtro XSS del navegador (legacy)",
}

def check_headers(url: str) -> dict:
    result = {"presente": [], "ausente": [], "raw": {}, "error": None}
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
        result["raw"] = dict(r.headers)
        for header, descripcion in SECURITY_HEADERS.items():
            if header.lower() in headers:
                result["presente"].append({"header": header, "valor": headers[header.lower()], "descripcion": descripcion})
            else:
                result["ausente"].append({"header": header, "descripcion": descripcion})
    except Exception as e:
        result["error"] = str(e)
    return result
