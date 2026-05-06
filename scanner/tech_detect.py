import requests
from bs4 import BeautifulSoup

FIRMAS = {
    "WordPress": ["wp-content", "wp-includes", "WordPress"],
    "Joomla": ["Joomla!", "/components/com_"],
    "Drupal": ["Drupal", "/sites/default/files"],
    "Shopify": ["cdn.shopify.com", "Shopify.theme"],
    "Wix": ["wix.com", "X-Wix-Published-Version"],
    "React": ["__NEXT_DATA__", "react-root", "_reactFiber"],
    "Vue.js": ["__vue__", "data-v-"],
    "jQuery": ["jquery", "jQuery"],
    "Bootstrap": ["bootstrap.min.css", "bootstrap.css"],
    "nginx": ["nginx"],
    "Apache": ["Apache"],
    "Cloudflare": ["cloudflare", "CF-Ray"],
    "PHP": ["X-Powered-By: PHP", ".php"],
    "ASP.NET": ["ASP.NET", "X-AspNet-Version", "__VIEWSTATE"],
}

def detect_technologies(url: str) -> dict:
    result = {"tecnologias": [], "servidor": None, "error": None}
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        contenido = r.text
        headers_str = str(r.headers)
        servidor = r.headers.get("Server", r.headers.get("X-Powered-By", None))
        result["servidor"] = servidor
        for tech, firmas in FIRMAS.items():
            for firma in firmas:
                if firma.lower() in contenido.lower() or firma.lower() in headers_str.lower():
                    if tech not in result["tecnologias"]:
                        result["tecnologias"].append(tech)
                    break
    except Exception as e:
        result["error"] = str(e)
    return result
