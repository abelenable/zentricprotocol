# Zentric Protocol — Setup Guide

## 1. Supabase — Tabla Waitlist

Ejecuta este SQL en **Supabase → SQL Editor**:

```sql
-- Crea la tabla de waitlist
CREATE TABLE waitlist (
  id         uuid        DEFAULT gen_random_uuid() PRIMARY KEY,
  email      text        NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now(),
  source     text        DEFAULT 'landing'
);

-- Activa Row Level Security
ALTER TABLE waitlist ENABLE ROW LEVEL SECURITY;

-- Permite inserts anónimos (formulario público)
CREATE POLICY "Allow anonymous inserts"
  ON waitlist
  FOR INSERT
  TO anon
  WITH CHECK (true);

-- Sólo tú puedes leer los datos (usa tu service_role key desde el backend)
CREATE POLICY "Owner can read"
  ON waitlist
  FOR SELECT
  USING (auth.role() = 'service_role');
```

---

## 2. Variables de entorno en Vercel

Ve a **Vercel → tu proyecto → Settings → Environment Variables** y añade:

| Variable               | Valor                              | Descripción                                      |
|------------------------|------------------------------------|--------------------------------------------------|
| `SUPABASE_URL`         | `https://xxxx.supabase.co`         | Project URL (Supabase → Settings → API)          |
| `SUPABASE_ANON_KEY`    | `eyJhbGci...`                      | anon/public key (Supabase → Settings → API)      |

> **Nota:** El `SUPABASE_ANON_KEY` (anon key) está diseñado para ser público.
> Es seguro usarlo en el HTML de la landing **siempre que RLS esté activado** (como arriba).
> El `service_role` key NUNCA debe ir en el frontend.

---

## 3. Conectar las claves al HTML

Abre `index.html` y busca estas líneas (aprox. línea 903):

```js
const SUPABASE_URL      = 'REPLACE_WITH_YOUR_SUPABASE_URL';
const SUPABASE_ANON_KEY = 'REPLACE_WITH_YOUR_SUPABASE_ANON_KEY';
```

Reemplaza los valores con los de tu proyecto Supabase.

---

## 4. Redes sociales — Actualizar handles

Busca en `index.html` el bloque con el comentario `<!-- SOCIAL LINKS -->` y actualiza las URLs:

| Red        | URL actual (placeholder)                                  | Reemplaza con       |
|------------|-----------------------------------------------------------|---------------------|
| X/Twitter  | `https://x.com/zentricprotocol`                           | tu @handle real     |
| Instagram  | `https://instagram.com/zentricprotocol`                   | tu @handle real     |
| LinkedIn   | `https://linkedin.com/company/zentricprotocol`            | tu company slug     |
| GitHub     | `https://github.com/zentricprotocol`                      | tu org/repo real    |

También actualiza en `<head>`:
```html
<meta name="twitter:site" content="@zentricprotocol">
<meta name="twitter:creator" content="@zentricprotocol">
```

Y en el JSON-LD Schema (`sameAs` array):
```json
"sameAs": [
  "https://x.com/TU_HANDLE",
  ...
]
```

---

## 5. Imagen Open Graph

Asegúrate de tener `/og.png` en la raíz del repositorio (1200×630px).
Referenciada en:
- `<meta property="og:image" content="https://zentricprotocol.com/og.png">`
- `<meta name="twitter:image" content="https://zentricprotocol.com/og.png">`

Si no tienes una aún, puedes usar una captura de pantalla de la landing o generarla con Figma.

---

## 6. Verificar el Schema.org

Valida el JSON-LD con: https://search.google.com/test/rich-results
Valida las Twitter Cards con: https://cards-dev.twitter.com/validator
Valida Open Graph con: https://www.opengraph.xyz/

---

## 7. Ver los leads de la Waitlist

En **Supabase → Table Editor → waitlist** verás todos los registros.
También puedes exportarlos a CSV desde el dashboard.
