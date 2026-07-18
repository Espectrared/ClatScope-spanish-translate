# 🛡️ ClatScope: Guía Rápida

### ¿De qué se trata?
ClatScope es una herramienta de **OSINT** (Inteligencia de Fuentes Abiertas) y ciberseguridad diseñada para hacer reconocimiento en internet. Básicamente, se encarga de **rastrear, recopilar y centralizar información pública** sobre un objetivo específico (como una persona, un correo, una IP o un dominio) para que no tengas que buscarla manualmente en decenas de sitios web diferentes.

---

## 👥 Las 2 Versiones Disponibles

*   **ClatScope Mini:** Es la versión ligera. Funciona de inmediato sin configurar nada y realiza búsquedas automatizadas básicas en la web.
*   **ClatScope Info Tool:** Es la versión avanzada y completa. Requiere conectar claves de acceso (APIs) de otros servicios para desbloquear todo su potencial de rastreo profundo.

---

## 🚀 Funcionalidades Principales (Agrupadas)

La herramienta se divide en estas áreas clave:

*   **Investigación de Personas y Usuarios:** Rastrea si un alias de usuario existe en más de 250 redes sociales[cite: 1], busca información pública asociada a nombres y valida datos de números telefónicos[cite: 1].
*   **Auditoría de Correos:** Analiza las rutas e IPs desde donde se envió un email[cite: 1] y verifica si una cuenta de correo ha sido expuesta en filtraciones de seguridad o hackeos masivos.
*   **Análisis de Sitios Web y Dominios:** Extrae registros DNS (A, MX, NS)[cite: 1], realiza consultas de propiedad legal (WHOIS)[cite: 1] e inspecciona certificados de seguridad SSL[cite: 1].
*   **Análisis Forense de Archivos (Metadata):** Extrae información oculta dentro de imágenes (incluyendo coordenadas GPS si las tiene)[cite: 1], documentos PDF[cite: 1], archivos de Office (Word, Excel, PowerPoint)[cite: 1] y pistas de audio[cite: 1].
*   **Rastreo Avanzado de Infraestructura:** Incluye escáneres básicos de puertos de red[cite: 1], calculadoras de firmas criptográficas (Hashes MD5, SHA256)[cite: 1] e integraciones para buscar buques marítimos o aeronaves en vivo[cite: 1].

---

## 🛠️ Instalación Express

Para correr la herramienta en tu máquina, solo necesitas abrir tu terminal y ejecutar estos comandos:

```bash
# 1. Clonar el repositorio oficial
git clone [https://github.com/Clats97/ClatScope.git](https://github.com/Clats97/ClatScope.git)

# 2. Entrar a la carpeta del proyecto
cd ClatScope

# 3. Instalar las librerías necesarias
pip install -r requirements.txt
