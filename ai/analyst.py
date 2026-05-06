from openai import OpenAI
import os

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def construir_resumen(resultados: dict) -> str:
    prompt = f"""Eres un experto en ciberseguridad. Analiza estos resultados de un escaneo básico no destructivo
de un sitio web y genera lo siguiente en español:

1. **Resumen ejecutivo** (2-3 oraciones, lenguaje no técnico)
2. **Hallazgos principales** con nivel de riesgo (Alto/Medio/Bajo) para cada uno
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
    return r.choices[0].message.content

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
