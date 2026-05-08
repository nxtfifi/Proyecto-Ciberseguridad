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

def _build_fingerprint(r) -> dict:
    soup = BeautifulSoup(r.text, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else None

    metas = []
    for meta in soup.find_all("meta"):
        name = meta.get("name") or meta.get("property") or meta.get("http-equiv")
        content = meta.get("content")
        if name and content:
            metas.append({"name": name, "content": content[:200]})

    scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
    links = [l.get("href") for l in soup.find_all("link") if l.get("href")]

    return {
        "headers": dict(r.headers),
        "cookies": list(r.cookies.keys()),
        "title": title,
        "metas": metas[:20],
        "scripts": scripts[:30],
        "links": links[:30],
    }


def detect_technologies(url: str) -> dict:
    result = {"tecnologias": [], "servidor": None, "error": None, "fingerprint": None}
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
        result["fingerprint"] = _build_fingerprint(r)
    except Exception as e:
        result["error"] = str(e)
    return result
