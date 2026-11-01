# Vínora para Render

Proyecto preparado como aplicación Node.js + Express + PostgreSQL. Incluye registro e inicio de sesión en servidor, contraseñas con bcrypt y recuperación mediante enlace temporal de 30 minutos enviado con Resend.

## Antes de publicar
1. Sube esta carpeta a un repositorio de GitHub.
2. En Render elige **New → Blueprint** y conecta el repositorio que contiene `render.yaml`.
3. Render creará el servicio web y la base PostgreSQL. Para una prueba inicial puedes elegir los planes gratuitos.
4. En el servicio, configura estas variables:
   - `APP_URL`: URL pública de tu servicio, por ejemplo `https://vinora.onrender.com`.
   - `RESEND_API_KEY`: clave API de Resend (no la publiques ni la subas a GitHub).
   - `EMAIL_FROM`: remitente verificado en Resend, por ejemplo `Vínora <cuentas@tudominio.com>`.
5. Guarda y despliega. Comprueba `https://TU-SERVICIO.onrender.com/api/health`.

## Correo
La recuperación real requiere una cuenta en Resend y un dominio/remitente verificado. Render Free bloquea SMTP saliente en puertos comunes; por eso se usa la API HTTPS de Resend. No pongas claves privadas en el código, HTML ni repositorio.

## Límites de esta primera conexión
El servidor guarda las cuentas y autentica registro/login/recuperación. El muro, publicaciones, comentarios, likes y fotos de perfil de esta versión todavía se guardan en el navegador del dispositivo, no en PostgreSQL; para convertir Vínora en una red social multiusuario completa habrá que migrar esos datos a la API y añadir almacenamiento de imágenes y moderación.

## Nota sobre el plan gratuito
Render indica que los servicios web gratuitos se duermen tras 15 minutos sin tráfico y tardan alrededor de un minuto en reactivarse. Las bases PostgreSQL gratuitas expiran a los 30 días y no tienen copias de seguridad. Es adecuado para pruebas, no para usuarios reales ni datos importantes. Revisa los límites vigentes antes de publicar.
