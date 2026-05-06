import socket

PUERTOS_COMUNES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP (Escritorio Remoto)",
    8080: "HTTP alternativo",
    8443: "HTTPS alternativo",
}

def scan_ports(url: str) -> dict:
    result = {"abiertos": [], "cerrados": [], "hostname": None, "error": None}
    try:
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
        result["hostname"] = hostname
        for puerto, servicio in PUERTOS_COMUNES.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            estado = sock.connect_ex((hostname, puerto))
            sock.close()
            if estado == 0:
                result["abiertos"].append({"puerto": puerto, "servicio": servicio})
            else:
                result["cerrados"].append({"puerto": puerto, "servicio": servicio})
    except Exception as e:
        result["error"] = str(e)
    return result
