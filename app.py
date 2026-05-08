import streamlit as st
import json
from dotenv import load_dotenv

load_dotenv()

from scanner.headers import check_headers
from scanner.ssl_check import check_ssl
from scanner.tech_detect import detect_technologies
from scanner.ports import scan_ports
from scanner.forms import detect_forms
from scanner.exposure import check_exposure
from ai.analyst import construir_resumen, chat_bot, detectar_tecnologias_ia

st.set_page_config(page_title="WebSec Analyzer", page_icon="🔐", layout="wide")

st.title("🔐 WebSec Analyzer")
st.caption("Asistente inteligente para análisis básico de seguridad web — uso académico y autorizado")

if "resultados" not in st.session_state:
    st.session_state.resultados = None
if "resumen_ia" not in st.session_state:
    st.session_state.resumen_ia = None
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

col_scan, col_chat = st.columns([1.2, 1])

with col_scan:
    st.subheader("Análisis de seguridad")

    with st.form("scan_form", clear_on_submit=False):
        url = st.text_input("URL del sitio autorizado", placeholder="https://ejemplo.com")
        submit = st.form_submit_button("🔍 Analizar", type="primary")

    if submit and url:
        with st.spinner("Ejecutando análisis..."):
            resultados = {}

            with st.status("Verificando headers HTTP..."):
                resultados["headers"] = check_headers(url)
            with st.status("Validando SSL/TLS..."):
                resultados["ssl"] = check_ssl(url)
            with st.status("Detectando tecnologías..."):
                resultados["tecnologias"] = detect_technologies(url)
                fp = resultados["tecnologias"].get("fingerprint")
                if fp:
                    ia_techs = detectar_tecnologias_ia(fp)
                    existentes = {t.lower() for t in resultados["tecnologias"]["tecnologias"]}
                    for t in ia_techs:
                        if t.lower() not in existentes:
                            resultados["tecnologias"]["tecnologias"].append(t)
                            existentes.add(t.lower())
            with st.status("Escaneando puertos..."):
                resultados["puertos"] = scan_ports(url)
            with st.status("Detectando formularios..."):
                resultados["formularios"] = detect_forms(url)
            with st.status("Revisando rutas expuestas..."):
                resultados["exposicion"] = check_exposure(url)
            with st.status("Generando análisis con IA..."):
                resumen = construir_resumen(json.dumps(resultados, ensure_ascii=False, indent=2))

            st.session_state.resultados = resultados
            st.session_state.resumen_ia = resumen
            st.session_state.chat_history = []

    if st.session_state.resultados:
        r = st.session_state.resultados

        st.markdown("---")
        st.subheader("📊 Análisis de la IA")
        st.markdown(st.session_state.resumen_ia, unsafe_allow_html=True)

        st.markdown("---")
        st.subheader("🔎 Resultados detallados")

        with st.expander("🛡️ Encabezados HTTP de seguridad"):
            h = r["headers"]
            if h["ausente"]:
                st.error(f"**{len(h['ausente'])} headers faltantes:**")
                for item in h["ausente"]:
                    st.markdown(f"- ❌ `{item['header']}` — {item['descripcion']}")
            if h["presente"]:
                st.success(f"**{len(h['presente'])} headers presentes:**")
                for item in h["presente"]:
                    st.markdown(f"- ✅ `{item['header']}`")

        with st.expander("🔒 SSL / TLS"):
            s = r["ssl"]
            if s.get("error"):
                st.error(f"Error: {s['error']}")
            else:
                cols = st.columns(3)
                cols[0].metric("HTTPS", "✅ Sí" if s["https"] else "❌ No")
                cols[1].metric("Cert. válido", "✅ Sí" if s["certificado_valido"] else "❌ No")
                cols[2].metric("Días restantes", s.get("dias_restantes", "N/A"))
                st.markdown(f"**Versión TLS:** `{s.get('version_tls', 'N/A')}`")
                st.markdown(f"**Emisor:** {s.get('emisor', 'N/A')}")

        with st.expander("🖥️ Tecnologías detectadas"):
            t = r["tecnologias"]
            if t.get("error"):
                st.error(t["error"])
            else:
                if t["servidor"]:
                    st.markdown(f"**Servidor:** `{t['servidor']}`")
                if t["tecnologias"]:
                    st.markdown("**Tecnologías:** " + ", ".join(f"`{x}`" for x in t["tecnologias"]))
                else:
                    st.info("No se detectaron tecnologías conocidas")

        with st.expander("🔌 Puertos visibles"):
            p = r["puertos"]
            if p.get("error"):
                st.error(p["error"])
            else:
                if p["abiertos"]:
                    st.warning(f"**{len(p['abiertos'])} puertos abiertos:**")
                    for item in p["abiertos"]:
                        st.markdown(f"- 🟡 Puerto **{item['puerto']}** — {item['servicio']}")
                else:
                    st.success("No se detectaron puertos adicionales abiertos")

        with st.expander("📝 Formularios detectados"):
            f = r["formularios"]
            if f.get("error"):
                st.error(f["error"])
            else:
                st.markdown(f"**Total de formularios:** {f['total']}")
                if f["tiene_password"]:
                    st.warning("⚠️ Se detectaron campos de contraseña")
                for i, form in enumerate(f["formularios"]):
                    st.markdown(f"**Formulario {i+1}** — Método: `{form['metodo']}` | Acción: `{form['accion']}`")

        with st.expander("🚨 Rutas y archivos expuestos"):
            e = r["exposicion"]
            if e.get("error"):
                st.error(e["error"])
            else:
                if e["expuesto"]:
                    for item in e["expuesto"]:
                        color = "🔴" if item["riesgo"] == "Alto" else "🟡"
                        st.markdown(f"{color} `{item['ruta']}` — HTTP {item['status']} — Riesgo: **{item['riesgo']}**")
                else:
                    st.success("No se encontraron rutas sensibles expuestas")

with col_chat:
    with st.expander("⚖️ Términos y condiciones"):
        st.markdown(
            "**WebSec Analyzer** es una herramienta con fines exclusivamente "
            "**académicos y de auditoría autorizada**.\n\n"
            "Los autores **no se hacen responsables** por el uso ilícito, "
            "anti-ético o no autorizado que se le dé a esta herramienta. "
            "Se recomienda **siempre** efectuar las pruebas únicamente sobre "
            "dominios previamente autorizados por sus propietarios o el "
            "representante legal correspondiente.\n\n"
            "El uso de esta herramienta implica la aceptación íntegra de "
            "estos términos."
        )

    st.subheader("💬 Asistente de seguridad")

    if not st.session_state.resultados:
        st.info("Ejecuta un análisis primero para activar el asistente.")
    else:
        chat_container = st.container(height=450)
        with chat_container:
            for msg in st.session_state.chat_history:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])

        pregunta = st.chat_input("Pregúntame sobre los hallazgos...")
        if pregunta:
            st.session_state.chat_history.append({"role": "user", "content": pregunta})
            with st.spinner("Analizando..."):
                respuesta = chat_bot(
                    st.session_state.chat_history[:-1],
                    pregunta,
                    json.dumps(st.session_state.resultados, ensure_ascii=False, indent=2)
                )
            st.session_state.chat_history.append({"role": "assistant", "content": respuesta})
            st.rerun()

st.markdown("---")
st.markdown(
    "<div style='text-align:center; color:#888; font-size:0.85rem; padding:1rem 0;'>"
    "© 2026 <b>WebSec Analyzer</b> — Felix Alejandro García García &amp; Emiliano Mendoza Vázquez. "
    "Todos los derechos reservados."
    "</div>",
    unsafe_allow_html=True,
)
