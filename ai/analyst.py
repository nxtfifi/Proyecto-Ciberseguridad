from openai import OpenAI
import os
import re
import json

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

_RISK_COLORS = {"alto": "#d32f2f", "medio": "#f9a825", "bajo": "#2e7d32"}

def _colorize_risk(text: str) -> str:
    def repl(m):
        word = m.group(1)
        color = _RISK_COLORS[word.lower()]
        return f'<span style="color:{color};font-weight:bold;">{word}</span>'
    return re.sub(r'\*\*(Alto|Medio|Bajo)\*\*', repl, text, flags=re.IGNORECASE)

def construir_resumen(resultados: dict) -> str:
    prompt = f"""Eres un experto en ciberseguridad. Analiza estos resultados de un escaneo básico no destructivo
de un sitio web y genera lo siguiente en español:

1. **Resumen ejecutivo** (2-3 oraciones, lenguaje no técnico)
2. **Hallazgos principales**: preséntalo OBLIGATORIAMENTE como una tabla markdown con exactamente estas columnas:

| Hallazgo | Descripción | Nivel de riesgo |
|----------|-------------|-----------------|
| ... | ... | **Alto** |

IMPORTANTE: en la columna "Nivel de riesgo" escribe SIEMPRE el valor entre dobles asteriscos exactamente como **Alto**, **Medio** o **Bajo** (sin otra palabra entre los asteriscos, sin texto adicional en la celda).
3. **Impacto** de los 2 problemas más críticos
4. **Mitigaciones recomendadas** (top 3, concretas y accionables)

Resultados del escaneo:
{resultados}

Responde con formato markdown claro."""

    r = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
    )
    return _colorize_risk(r.choices[0].message.content)

def chat_bot(historial: list, pregunta: str, resultados: dict) -> str:
    sistema = f"""Eres un asistente de ciberseguridad especializado.
El usuario analizó un sitio web y estos son los resultados del escaneo:

{resultados}

Responde las preguntas del usuario sobre estos resultados en español.
Sé claro, directo y usa lenguaje accesible. Si te preguntan algo fuera del escaneo,
redirígelos al análisis actual."""

    mensajes = [{"role": "system", "content": sistema}]
    for h in historial:
        mensajes.append(h)
    mensajes.append({"role": "user", "content": pregunta})

    r = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=mensajes,
        temperature=0.5,
    )
    return r.choices[0].message.content


def detectar_tecnologias_ia(fingerprint: dict) -> list:
    if not fingerprint:
        return []

    datos = json.dumps(fingerprint, ensure_ascii=False, default=str)[:8000]
    prompt = f"""Eres un experto en fingerprinting web (similar a la herramienta whatweb de Kali Linux).
Analiza estos datos crudos extraídos de la respuesta HTTP de un sitio (headers, cookies, title, meta tags, scripts y links) e identifica las tecnologías presentes.

Detecta: CMS, frameworks frontend/backend, librerías JS, servidores web, lenguajes, CDN, herramientas de analítica, sistemas de pago, builders/page builders, fonts, etc.

Datos crudos:
{datos}

Responde EXCLUSIVAMENTE con un JSON array de strings con los nombres de las tecnologías detectadas, sin explicación, sin markdown, sin texto adicional.
Ejemplo de respuesta correcta: ["WordPress", "PHP", "Cloudflare", "jQuery", "Google Analytics"]"""

    try:
        r = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
        )
        raw = r.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = raw.strip("`")
            if raw.lower().startswith("json"):
                raw = raw[4:].strip()
        techs = json.loads(raw)
        if isinstance(techs, list):
            return [str(t).strip() for t in techs if str(t).strip()]
    except Exception:
        return []
    return []
