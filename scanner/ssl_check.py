import ssl
import socket
from datetime import datetime

def check_ssl(url: str) -> dict:
    result = {"https": False, "certificado_valido": False, "expira": None, "dias_restantes": None,
              "version_tls": None, "emisor": None, "sujeto": None, "error": None}
    try:
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
        result["https"] = url.startswith("https://")
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=10), server_hostname=hostname) as s:
            cert = s.getpeercert()
            result["version_tls"] = s.version()
            result["certificado_valido"] = True
            expira_str = cert.get("notAfter", "")
            if expira_str:
                expira = datetime.strptime(expira_str, "%b %d %H:%M:%S %Y %Z")
                result["expira"] = expira.strftime("%Y-%m-%d")
                result["dias_restantes"] = (expira - datetime.utcnow()).days
            emisor = dict(x[0] for x in cert.get("issuer", []))
            sujeto = dict(x[0] for x in cert.get("subject", []))
            result["emisor"] = emisor.get("organizationName", "Desconocido")
            result["sujeto"] = sujeto.get("commonName", hostname)
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificado inválido: {e}"
    except Exception as e:
        result["error"] = str(e)
    return result
