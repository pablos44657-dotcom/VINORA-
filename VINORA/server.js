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
app.use(express.json({ limit: '8mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Las tablas nuevas se crean sin borrar las cuentas existentes.
await pool.query(`
CREATE TABLE IF NOT EXISTS users (
 id BIGSERIAL PRIMARY KEY, name VARCHAR(80) NOT NULL, email VARCHAR(254) UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, reset_token_hash TEXT, reset_expires TIMESTAMPTZ,
 bio VARCHAR(500) NOT NULL DEFAULT '', avatar TEXT, is_private BOOLEAN NOT NULL DEFAULT FALSE,
 theme VARCHAR(20) NOT NULL DEFAULT 'sand', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS bio VARCHAR(500) NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_private BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS theme VARCHAR(20) NOT NULL DEFAULT 'sand';
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS posts (
 id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 body VARCHAR(5000) NOT NULL DEFAULT '', image TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS post_likes (
 post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 PRIMARY KEY(post_id,user_id)
);
CREATE TABLE IF NOT EXISTS comments (
 id BIGSERIAL PRIMARY KEY, post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 body VARCHAR(500) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS saved_posts (
 user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(user_id,post_id)
);
CREATE TABLE IF NOT EXISTS follows (
 follower_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 following_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(follower_id,following_id), CHECK(follower_id<>following_id)
);
CREATE TABLE IF NOT EXISTS follow_requests (
 requester_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 target_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(requester_id,target_id), CHECK(requester_id<>target_id)
);
CREATE TABLE IF NOT EXISTS stories (
 id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 media TEXT NOT NULL, caption VARCHAR(300) NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW()+INTERVAL '24 hours')
);
CREATE TABLE IF NOT EXISTS conversations (
 id BIGSERIAL PRIMARY KEY, user_one BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 user_two BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CHECK(user_one<user_two), UNIQUE(user_one,user_two)
);
CREATE TABLE IF NOT EXISTS messages (
 id BIGSERIAL PRIMARY KEY, conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
 sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 body VARCHAR(2000) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS posts_created_idx ON posts(created_at DESC);
CREATE INDEX IF NOT EXISTS stories_expiry_idx ON stories(expires_at);
CREATE INDEX IF NOT EXISTS messages_conversation_idx ON messages(conversation_id,created_at);
`);

const emailValid = value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const publicUser = u => ({ id: String(u.id), name: u.name, bio: u.bio || '', avatar: u.avatar || null, isPrivate: !!u.is_private, theme: u.theme || 'sand' });
function cookie(req, name) {
 const raw = req.headers.cookie || '';
 const part = raw.split(';').map(v => v.trim()).find(v => v.startsWith(name + '='));
 return part ? decodeURIComponent(part.slice(name.length + 1)) : '';
}
async function createSession(userId, res) {
 const token = crypto.randomBytes(32).toString('hex');
 await pool.query('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL \'30 days\')', [hash(token), userId]);
 res.cookie('vinora_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/', maxAge: 30*24*60*60*1000 });
}
async function auth(req,res,next) {
 try {
  const token = cookie(req,'vinora_session');
  if (!token) return res.status(401).json({error:'Inicia sesión para continuar.'});
  const result = await pool.query(`SELECT u.id,u.name,u.email,u.bio,u.avatar,u.is_private,u.theme
    FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW()`, [hash(token)]);
  if (!result.rowCount) return res.status(401).json({error:'Tu sesión venció. Inicia sesión nuevamente.'});
  req.user = result.rows[0]; next();
 } catch(e) { next(e); }
}
const validImage = value => typeof value === 'string' && /^data:image\/(jpeg|png|webp|gif);base64,/.test(value) && value.length <= 6*1024*1024;
const postSelect = `SELECT p.id,p.user_id,p.body,p.image,p.created_at,u.name,u.avatar,u.is_private,
 (SELECT COUNT(*) FROM post_likes l WHERE l.post_id=p.id)::int AS likes,
 EXISTS(SELECT 1 FROM post_likes l WHERE l.post_id=p.id AND l.user_id=$1) AS liked,
 EXISTS(SELECT 1 FROM saved_posts s WHERE s.post_id=p.id AND s.user_id=$1) AS saved,
 (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id)::int AS comment_count
 FROM posts p JOIN users u ON u.id=p.user_id`;
async function canSeeProfile(viewerId, ownerId) {
 if (String(viewerId)===String(ownerId)) return true;
 const q=await pool.query('SELECT is_private FROM users WHERE id=$1',[ownerId]);
 if (!q.rowCount || !q.rows[0].is_private) return true;
 const f=await pool.query('SELECT 1 FROM follows WHERE follower_id=$1 AND following_id=$2',[viewerId,ownerId]);
 return !!f.rowCount;
}

app.get('/api/health', (_req,res)=>res.json({ok:true,service:'Vinora API',version:2}));
app.post('/api/register', async(req,res)=>{
 try {
  const name=String(req.body.name||'').trim(), email=String(req.body.email||'').trim().toLowerCase(), password=String(req.body.password||'');
  if(name.length<2||name.length>80||!emailValid(email)||password.length<8||password.length>200) return res.status(400).json({error:'Revisa tu nombre, correo y contraseña (mínimo 8 caracteres).'});
  const ph=await bcrypt.hash(password,12);
  const r=await pool.query('INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email,bio,avatar,is_private,theme',[name,email,ph]);
  await createSession(r.rows[0].id,res); res.status(201).json({user:publicUser(r.rows[0])});
 } catch(e){if(e.code==='23505')return res.status(409).json({error:'Ese correo ya está registrado.'});console.error('register',e.message);res.status(500).json({error:'No se pudo crear la cuenta.'});}
});
app.post('/api/login',async(req,res)=>{
 try{const email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');const r=await pool.query('SELECT * FROM users WHERE email=$1',[email]);const u=r.rows[0];if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:'Correo o contraseña incorrectos.'});await createSession(u.id,res);res.json({user:publicUser(u)});}
 catch(e){console.error('login',e.message);res.status(500).json({error:'No se pudo iniciar sesión.'});}
});
app.get('/api/me',auth,(req,res)=>res.json({user:publicUser(req.user)}));
app.post('/api/logout',async(req,res)=>{const t=cookie(req,'vinora_session');if(t)await pool.query('DELETE FROM sessions WHERE token_hash=$1',[hash(t)]);res.clearCookie('vinora_session',{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',path:'/'});res.json({ok:true});});
app.put('/api/profile',auth,async(req,res)=>{
 const name=String(req.body.name||'').trim(),bio=String(req.body.bio||'').trim(),avatar=req.body.avatar===null?null:req.body.avatar;
 if(name.length<2||name.length>80||bio.length>500)return res.status(400).json({error:'Revisa el nombre o la biografía.'});
 if(avatar!==null&&!validImage(avatar))return res.status(400).json({error:'La foto no es válida o supera el límite de tamaño.'});
 const r=await pool.query('UPDATE users SET name=$1,bio=$2,avatar=$3 WHERE id=$4 RETURNING id,name,bio,avatar,is_private,theme',[name,bio,avatar,req.user.id]);res.json({user:publicUser(r.rows[0])});
});
app.put('/api/settings',auth,async(req,res)=>{
 const isPrivate=!!req.body.isPrivate,theme=['sand','light','dark','sage','rose'].includes(req.body.theme)?req.body.theme:'sand';
 const r=await pool.query('UPDATE users SET is_private=$1,theme=$2 WHERE id=$3 RETURNING id,name,bio,avatar,is_private,theme',[isPrivate,theme,req.user.id]);res.json({user:publicUser(r.rows[0])});
});
app.get('/api/profiles',auth,async(req,res)=>{
 const q=String(req.query.q||'').trim().slice(0,80);if(!q)return res.json({users:[]});
 const r=await pool.query(`SELECT id,name,bio,avatar,is_private,theme FROM users WHERE id<>$1 AND name ILIKE $2 ORDER BY name LIMIT 30`,[req.user.id,`%${q}%`]);res.json({users:r.rows.map(publicUser)});
});
app.get('/api/profiles/:id',auth,async(req,res)=>{
 const r=await pool.query('SELECT id,name,bio,avatar,is_private,theme FROM users WHERE id=$1',[req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Perfil no encontrado.'});
 const u=r.rows[0],allowed=await canSeeProfile(req.user.id,u.id);
 const [followers,following,relation]=await Promise.all([
  pool.query('SELECT COUNT(*)::int n FROM follows WHERE following_id=$1',[u.id]),pool.query('SELECT COUNT(*)::int n FROM follows WHERE follower_id=$1',[u.id]),
  pool.query('SELECT EXISTS(SELECT 1 FROM follows WHERE follower_id=$1 AND following_id=$2) following, EXISTS(SELECT 1 FROM follow_requests WHERE requester_id=$1 AND target_id=$2) pending',[req.user.id,u.id])
 ]);
 let posts=[];if(allowed){const p=await pool.query(`${postSelect} WHERE p.user_id=$2 ORDER BY p.created_at DESC LIMIT 50`,[req.user.id,u.id]);posts=p.rows.map(formatPost)}
 res.json({user:publicUser(u),allowed,followers:followers.rows[0].n,following:following.rows[0].n,isFollowing:relation.rows[0].following,requestPending:relation.rows[0].pending,posts});
});
app.post('/api/follow/:id',auth,async(req,res)=>{
 const target=String(req.params.id);if(target===String(req.user.id))return res.status(400).json({error:'No puedes seguirte a ti mismo.'});
 const u=await pool.query('SELECT is_private FROM users WHERE id=$1',[target]);if(!u.rowCount)return res.status(404).json({error:'Usuario no encontrado.'});
 if(u.rows[0].is_private){await pool.query('INSERT INTO follow_requests(requester_id,target_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[req.user.id,target]);return res.json({pending:true});}
 await pool.query('INSERT INTO follows(follower_id,following_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[req.user.id,target]);res.json({following:true});
});
app.get('/api/follow-requests',auth,async(req,res)=>{const r=await pool.query('SELECT fr.requester_id,u.name,u.avatar FROM follow_requests fr JOIN users u ON u.id=fr.requester_id WHERE fr.target_id=$1 ORDER BY fr.created_at DESC',[req.user.id]);res.json({requests:r.rows.map(x=>({id:String(x.requester_id),name:x.name,avatar:x.avatar}))});});
app.post('/api/follow-requests/:id/:decision',auth,async(req,res)=>{const id=req.params.id;if(!['accept','reject'].includes(req.params.decision))return res.status(400).json({error:'Acción no válida.'});const c=await pool.query('DELETE FROM follow_requests WHERE requester_id=$1 AND target_id=$2 RETURNING requester_id',[id,req.user.id]);if(!c.rowCount)return res.status(404).json({error:'Solicitud no encontrada.'});if(req.params.decision==='accept')await pool.query('INSERT INTO follows(follower_id,following_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[id,req.user.id]);res.json({ok:true});});
function formatPost(p){return{id:String(p.id),userId:String(p.user_id),name:p.name,avatar:p.avatar,body:p.body,image:p.image,createdAt:p.created_at,likes:p.likes,liked:p.liked,saved:p.saved,commentCount:p.comment_count};}
app.get('/api/posts',auth,async(req,res)=>{const r=await pool.query(`${postSelect} WHERE p.user_id=$1 OR p.user_id IN (SELECT following_id FROM follows WHERE follower_id=$1) OR (u.is_private=FALSE) ORDER BY p.created_at DESC LIMIT 60`,[req.user.id]);res.json({posts:r.rows.map(formatPost)});});
app.post('/api/posts',auth,async(req,res)=>{const body=String(req.body.body||'').trim(),image=req.body.image||null;if(!body&&!image)return res.status(400).json({error:'Escribe algo o añade una imagen.'});if(body.length>5000||(image&&!validImage(image)))return res.status(400).json({error:'El contenido o la imagen supera el límite permitido.'});const r=await pool.query('INSERT INTO posts(user_id,body,image) VALUES($1,$2,$3) RETURNING id',[req.user.id,body,image]);const p=await pool.query(`${postSelect} WHERE p.id=$2`,[req.user.id,r.rows[0].id]);res.status(201).json({post:formatPost(p.rows[0])});});
app.delete('/api/posts/:id',auth,async(req,res)=>{const r=await pool.query('DELETE FROM posts WHERE id=$1 AND user_id=$2',[req.params.id,req.user.id]);if(!r.rowCount)return res.status(404).json({error:'Publicación no encontrada.'});res.json({ok:true});});
app.post('/api/posts/:id/like',auth,async(req,res)=>{const id=req.params.id;if(!(await canSeePost(req.user.id,id)))return res.status(404).json({error:'Publicación no encontrada.'});const exists=await pool.query('SELECT 1 FROM post_likes WHERE post_id=$1 AND user_id=$2',[id,req.user.id]);if(exists.rowCount)await pool.query('DELETE FROM post_likes WHERE post_id=$1 AND user_id=$2',[id,req.user.id]);else await pool.query('INSERT INTO post_likes(post_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[id,req.user.id]);res.json({liked:!exists.rowCount});});
app.get('/api/posts/:id/comments',auth,async(req,res)=>{if(!(await canSeePost(req.user.id,req.params.id)))return res.status(404).json({error:'Publicación no encontrada.'});const r=await pool.query('SELECT c.id,c.body,c.created_at,u.id user_id,u.name,u.avatar FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=$1 ORDER BY c.created_at ASC',[req.params.id]);res.json({comments:r.rows.map(c=>({...c,id:String(c.id),userId:String(c.user_id)}))});});
app.post('/api/posts/:id/comments',auth,async(req,res)=>{if(!(await canSeePost(req.user.id,req.params.id)))return res.status(404).json({error:'Publicación no encontrada.'});const body=String(req.body.body||'').trim();if(!body||body.length>500)return res.status(400).json({error:'El comentario debe tener entre 1 y 500 caracteres.'});const r=await pool.query('INSERT INTO comments(post_id,user_id,body) SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM posts WHERE id=$1) RETURNING id,body,created_at',[req.params.id,req.user.id,body]);if(!r.rowCount)return res.status(404).json({error:'Publicación no encontrada.'});res.status(201).json({comment:{...r.rows[0],id:String(r.rows[0].id),userId:String(req.user.id),name:req.user.name}});});
app.get('/api/saved',auth,async(req,res)=>{const r=await pool.query(`${postSelect} JOIN saved_posts sp ON sp.post_id=p.id WHERE sp.user_id=$1 ORDER BY sp.created_at DESC`,[req.user.id]);res.json({posts:r.rows.map(formatPost)});});
app.post('/api/posts/:id/save',auth,async(req,res)=>{if(!(await canSeePost(req.user.id,req.params.id)))return res.status(404).json({error:'Publicación no encontrada.'});const exists=await pool.query('SELECT 1 FROM saved_posts WHERE user_id=$1 AND post_id=$2',[req.user.id,req.params.id]);if(exists.rowCount)await pool.query('DELETE FROM saved_posts WHERE user_id=$1 AND post_id=$2',[req.user.id,req.params.id]);else{const p=await pool.query('SELECT 1 FROM posts WHERE id=$1',[req.params.id]);if(!p.rowCount)return res.status(404).json({error:'Publicación no encontrada.'});await pool.query('INSERT INTO saved_posts(user_id,post_id) VALUES($1,$2)',[req.user.id,req.params.id]);}res.json({saved:!exists.rowCount});});
app.get('/api/stories',auth,async(req,res)=>{await pool.query('DELETE FROM stories WHERE expires_at<=NOW()');const r=await pool.query(`SELECT s.id,s.user_id,s.media,s.caption,s.created_at,s.expires_at,u.name,u.avatar FROM stories s JOIN users u ON u.id=s.user_id WHERE s.user_id=$1 OR s.user_id IN (SELECT following_id FROM follows WHERE follower_id=$1) OR u.is_private=FALSE ORDER BY s.created_at DESC`,[req.user.id]);res.json({stories:r.rows.map(s=>({...s,id:String(s.id),userId:String(s.user_id)}))});});
app.post('/api/stories',auth,async(req,res)=>{const media=req.body.media,caption=String(req.body.caption||'').trim().slice(0,300);if(!validImage(media))return res.status(400).json({error:'La historia debe ser una imagen válida de hasta 6 MB.'});const r=await pool.query('INSERT INTO stories(user_id,media,caption) VALUES($1,$2,$3) RETURNING id,media,caption,created_at,expires_at',[req.user.id,media,caption]);res.status(201).json({story:{...r.rows[0],id:String(r.rows[0].id),userId:String(req.user.id),name:req.user.name,avatar:req.user.avatar}});});
app.delete('/api/stories/:id',auth,async(req,res)=>{const r=await pool.query('DELETE FROM stories WHERE id=$1 AND user_id=$2',[req.params.id,req.user.id]);if(!r.rowCount)return res.status(404).json({error:'Historia no encontrada.'});res.json({ok:true});});
app.get('/api/conversations',auth,async(req,res)=>{const r=await pool.query(`SELECT c.id,other.id other_id,other.name,other.avatar,
 (SELECT body FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) last_message,
 (SELECT created_at FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) last_at
 FROM conversations c JOIN users other ON other.id=CASE WHEN c.user_one=$1 THEN c.user_two ELSE c.user_one END
 WHERE c.user_one=$1 OR c.user_two=$1 ORDER BY last_at DESC NULLS LAST`,[req.user.id]);res.json({conversations:r.rows.map(c=>({...c,id:String(c.id),otherId:String(c.other_id)}))});});
app.post('/api/conversations',auth,async(req,res)=>{const other=String(req.body.userId||'');if(!/^\d+$/.test(other)||other===String(req.user.id))return res.status(400).json({error:'Selecciona otra persona.'});const u=await pool.query('SELECT id,is_private FROM users WHERE id=$1',[other]);if(!u.rowCount)return res.status(404).json({error:'Usuario no encontrado.'});if(!(await canSeeProfile(req.user.id,other)))return res.status(403).json({error:'Debes seguir este perfil privado para enviarle mensajes.'});const a=Math.min(Number(req.user.id),Number(other)),b=Math.max(Number(req.user.id),Number(other));const r=await pool.query('INSERT INTO conversations(user_one,user_two) VALUES($1,$2) ON CONFLICT(user_one,user_two) DO UPDATE SET user_one=EXCLUDED.user_one RETURNING id',[a,b]);res.json({conversationId:String(r.rows[0].id)});});
async function conversationFor(id,userId){const r=await pool.query('SELECT id FROM conversations WHERE id=$1 AND (user_one=$2 OR user_two=$2)',[id,userId]);return !!r.rowCount;}
app.get('/api/conversations/:id/messages',auth,async(req,res)=>{if(!(await conversationFor(req.params.id,req.user.id)))return res.status(404).json({error:'Conversación no encontrada.'});const r=await pool.query('SELECT m.id,m.sender_id,m.body,m.created_at,u.name FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.conversation_id=$1 ORDER BY m.created_at ASC LIMIT 200',[req.params.id]);res.json({messages:r.rows.map(m=>({...m,id:String(m.id),senderId:String(m.sender_id)}))});});
app.post('/api/conversations/:id/messages',auth,async(req,res)=>{const body=String(req.body.body||'').trim();if(!body||body.length>2000)return res.status(400).json({error:'El mensaje debe tener entre 1 y 2000 caracteres.'});if(!(await conversationFor(req.params.id,req.user.id)))return res.status(404).json({error:'Conversación no encontrada.'});const r=await pool.query('INSERT INTO messages(conversation_id,sender_id,body) VALUES($1,$2,$3) RETURNING id,sender_id,body,created_at',[req.params.id,req.user.id,body]);res.status(201).json({message:{...r.rows[0],id:String(r.rows[0].id),senderId:String(req.user.id),name:req.user.name}});});

app.post('/api/forgot-password',async(req,res)=>{
 const email=String(req.body.email||'').trim().toLowerCase(),generic={message:'Si el correo está registrado, recibirás instrucciones para recuperar tu contraseña.'};if(!emailValid(email))return res.json(generic);
 try{const r=await pool.query('SELECT id FROM users WHERE email=$1',[email]);if(!r.rowCount)return res.json(generic);if(!process.env.RESEND_API_KEY||!process.env.EMAIL_FROM)return res.status(503).json({error:'La recuperación por correo aún no está configurada.'});const token=crypto.randomBytes(32).toString('hex'),tokenHash=hash(token);await pool.query("UPDATE users SET reset_token_hash=$1,reset_expires=NOW()+INTERVAL '30 minutes' WHERE id=$2",[tokenHash,r.rows[0].id]);const base=process.env.APP_URL||`${req.protocol}://${req.get('host')}`,link=`${base}/?reset=${token}`;const resend=new Resend(process.env.RESEND_API_KEY);await resend.emails.send({from:process.env.EMAIL_FROM,to:email,subject:'Recupera tu contraseña de Vínora',html:`<p>Recibimos una solicitud para cambiar tu contraseña de Vínora.</p><p><a href="${link}">Crear una contraseña nueva</a></p><p>Este enlace vence en 30 minutos.</p>`});res.json(generic);}catch(e){console.error('forgot',e.message);res.status(500).json({error:'No se pudo enviar el correo.'});}
});
app.post('/api/reset-password',async(req,res)=>{try{const token=String(req.body.token||''),password=String(req.body.password||'');if(password.length<8||password.length>200)return res.status(400).json({error:'La contraseña debe tener al menos 8 caracteres.'});const r=await pool.query('SELECT id FROM users WHERE reset_token_hash=$1 AND reset_expires>NOW()',[hash(token)]);if(!r.rowCount)return res.status(400).json({error:'El enlace no es válido o ya venció.'});const ph=await bcrypt.hash(password,12);await pool.query('UPDATE users SET password_hash=$1,reset_token_hash=NULL,reset_expires=NULL WHERE id=$2',[ph,r.rows[0].id]);await pool.query('DELETE FROM sessions WHERE user_id=$1',[r.rows[0].id]);res.json({message:'Contraseña actualizada. Ya puedes iniciar sesión.'});}catch(e){console.error('reset',e.message);res.status(500).json({error:'No se pudo cambiar la contraseña.'});}});

app.use((err,_req,res,_next)=>{console.error('API error',err.message);res.status(500).json({error:'Ocurrió un error interno. Inténtalo nuevamente.'});});
const port=process.env.PORT||3000;app.listen(port,'0.0.0.0',()=>console.log(`Vínora escuchando en ${port}`));
