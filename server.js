import express from 'express';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import { Resend } from 'resend';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { Pool } = pg;
const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false });
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));

await pool.query(`CREATE TABLE IF NOT EXISTS users (
 id BIGSERIAL PRIMARY KEY,
 name VARCHAR(80) NOT NULL,
 email VARCHAR(254) UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 reset_token_hash TEXT,
 reset_expires TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`);

const emailValid = value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'Vinora API' }));

app.post('/api/register', async (req, res) => {
 try {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (name.length < 2 || name.length > 80 || !emailValid(email) || password.length < 8 || password.length > 200)
   return res.status(400).json({ error: 'Revisa tu nombre, correo y contraseña (mínimo 8 caracteres).' });
  const password_hash = await bcrypt.hash(password, 12);
  const result = await pool.query('INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email', [name,email,password_hash]);
  res.status(201).json({ user: result.rows[0] });
 } catch (e) {
  if (e.code === '23505') return res.status(409).json({ error: 'Ese correo ya está registrado.' });
  console.error('register error', e.message); res.status(500).json({ error: 'No se pudo crear la cuenta.' });
 }
});

app.post('/api/login', async (req, res) => {
 try {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const result = await pool.query('SELECT id,name,email,password_hash FROM users WHERE email=$1', [email]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
  res.json({ user: { id: user.id, name: user.name, email: user.email } });
 } catch (e) { console.error('login error', e.message); res.status(500).json({ error: 'No se pudo iniciar sesión.' }); }
});

app.post('/api/forgot-password', async (req, res) => {
 const email = String(req.body.email || '').trim().toLowerCase();
 const generic = { message: 'Si el correo está registrado, recibirás instrucciones para recuperar tu contraseña.' };
 if (!emailValid(email)) return res.json(generic);
 try {
  const result = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
  if (!result.rowCount) return res.json(generic);
  if (!process.env.RESEND_API_KEY || !process.env.EMAIL_FROM) {
   console.error('Password reset email is not configured (RESEND_API_KEY / EMAIL_FROM).');
   return res.status(503).json({ error: 'La recuperación por correo aún no está configurada.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  await pool.query('UPDATE users SET reset_token_hash=$1, reset_expires=NOW()+INTERVAL \'30 minutes\' WHERE id=$2', [tokenHash, result.rows[0].id]);
  const base = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
  const link = `${base}/?reset=${token}`;
  const resend = new Resend(process.env.RESEND_API_KEY);
  await resend.emails.send({
   from: process.env.EMAIL_FROM,
   to: email,
   subject: 'Recupera tu contraseña de Vínora',
   html: `<p>Recibimos una solicitud para cambiar tu contraseña de Vínora.</p><p><a href="${link}">Crear una contraseña nueva</a></p><p>Este enlace vence en 30 minutos. Si no solicitaste el cambio, ignora este mensaje.</p>`
  });
  res.json(generic);
 } catch (e) { console.error('forgot password error', e.message); res.status(500).json({ error: 'No se pudo enviar el correo. Inténtalo más tarde.' }); }
});

app.post('/api/reset-password', async (req, res) => {
 try {
  const token = String(req.body.token || '');
  const password = String(req.body.password || '');
  if (password.length < 8 || password.length > 200) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres.' });
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const result = await pool.query('SELECT id FROM users WHERE reset_token_hash=$1 AND reset_expires > NOW()', [tokenHash]);
  if (!result.rowCount) return res.status(400).json({ error: 'El enlace no es válido o ya venció. Solicita otro.' });
  const hash = await bcrypt.hash(password, 12);
  await pool.query('UPDATE users SET password_hash=$1, reset_token_hash=NULL, reset_expires=NULL WHERE id=$2', [hash, result.rows[0].id]);
  res.json({ message: 'Contraseña actualizada. Ya puedes iniciar sesión.' });
 } catch (e) { console.error('reset password error', e.message); res.status(500).json({ error: 'No se pudo cambiar la contraseña.' }); }
});

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => console.log(`Vínora escuchando en ${port}`));
