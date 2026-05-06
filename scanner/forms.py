import requests
from bs4 import BeautifulSoup

def detect_forms(url: str) -> dict:
    result = {"formularios": [], "total": 0, "tiene_password": False, "error": None}
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        result["total"] = len(forms)
        for i, form in enumerate(forms):
            campos = []
            tiene_pass = False
            for inp in form.find_all(["input", "textarea", "select"]):
                tipo = inp.get("type", "text")
                nombre = inp.get("name", inp.get("id", f"campo_{i}"))
                campos.append({"tipo": tipo, "nombre": nombre})
                if tipo == "password":
                    tiene_pass = True
                    result["tiene_password"] = True
            result["formularios"].append({
                "accion": form.get("action", "(misma página)"),
                "metodo": form.get("method", "GET").upper(),
                "campos": campos,
                "tiene_password": tiene_pass,
            })
    except Exception as e:
        result["error"] = str(e)
    return result
