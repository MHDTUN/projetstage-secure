require('dotenv').config()
const express = require('express')
const helmet = require('helmet')
const rateLimit = require('express-rate-limit')
const { Pool } = require('pg')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const cors = require('cors')

const app = express()

app.use(cors())
app.use(helmet())
app.use(express.json())

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  validate: { xForwardedForHeader: false }
})
app.use(limiter)

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
})

// ============================================================================
// HELPERS
// ============================================================================

// Wrapper qui gère les try/catch automatiquement — évite la répétition partout
const route = (handler) => async (req, res) => {
  try {
    await handler(req, res)
  } catch (err) {
    console.error(`[${req.method} ${req.path}]`, err.message)
    res.status(500).json({ message: err.message })
  }
}

// Statuts autorisés
const STATUTS = ['ACTIF', 'TERMINE']
const validStatut = (s) => STATUTS.includes(s)

// ============================================================================
// HEALTH CHECK (utile pour réveiller Render et vérifier la base)
// ============================================================================

app.get('/', (req, res) => res.json({ status: 'ok', service: 'PCS API', version: '2.0' }))

app.get('/health', route(async (req, res) => {
  const db = await pool.query('SELECT NOW() AS now')
  res.json({ status: 'ok', db: 'connected', time: db.rows[0].now })
}))

// ============================================================================
// AUTH
// ============================================================================

app.post('/login', route(async (req, res) => {
  const { username, password } = req.body
  if (!username || !password) return res.status(400).json({ message: 'Champs requis' })
  const result = await pool.query('SELECT * FROM admpcs.utilisateurs WHERE username = $1', [username])
  const user = result.rows[0]
  if (!user) return res.status(401).json({ message: 'Identifiants incorrects' })
  const valide = await bcrypt.compare(password, user.password)
  if (!valide) return res.status(401).json({ message: 'Identifiants incorrects' })
  const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '8h' })
  res.json({ token, username })
}))

app.post('/inscription', route(async (req, res) => {
  const { username, password } = req.body
  if (!username || !password) return res.status(400).json({ message: 'Champs requis' })
  if (password.length < 4) return res.status(400).json({ message: 'Mot de passe trop court (min 4)' })
  const existe = await pool.query('SELECT 1 FROM admpcs.utilisateurs WHERE username = $1', [username])
  if (existe.rows.length) return res.status(409).json({ message: 'Nom d\'utilisateur déjà pris' })
  const hash = await bcrypt.hash(password, 10)
  await pool.query('INSERT INTO admpcs.utilisateurs (username, password) VALUES ($1, $2)', [username, hash])
  res.json({ message: 'Compte créé' })
}))

function verifierToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (!token) return res.status(403).json({ message: 'Token manquant' })
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Token invalide' })
    req.user = decoded
    next()
  })
}

// ============================================================================
// PROCESSUS
// ============================================================================

app.get('/processus', verifierToken, route(async (req, res) => {
  const result = await pool.query('SELECT * FROM admpcs.processus ORDER BY pcsnum')
  res.json(result.rows)
}))

app.post('/processus', verifierToken, route(async (req, res) => {
  const { pcsnom, pcsdsc, pcsstu, pcsrspgrp } = req.body
  if (!pcsnom || !pcsnom.trim()) return res.status(400).json({ message: 'Nom requis' })
  const r = await pool.query(
    'SELECT admpcs.app_ins_processus($1, $2, $3, $4) AS pcs_id',
    [pcsnom, pcsdsc || null, pcsstu || 'ACT', pcsrspgrp || 'ADMIN']
  )
  const pcs = await pool.query('SELECT * FROM admpcs.processus WHERE pcs_id = $1', [r.rows[0].pcs_id])
  res.json(pcs.rows[0])
}))

app.put('/processus/:id', verifierToken, route(async (req, res) => {
  const { pcsnom, pcsdsc, pcsrspgrp } = req.body
  await pool.query('SELECT admpcs.app_upd_processus($1, $2, $3, $4)',
    [req.params.id, pcsnom, pcsdsc || null, pcsrspgrp || 'ADMIN'])
  const pcs = await pool.query('SELECT * FROM admpcs.processus WHERE pcs_id = $1', [req.params.id])
  res.json(pcs.rows[0])
}))

// Changement de statut (ACTIF / TERMINE) — écrit directement dans la colonne statut
app.patch('/processus/:id/statut', verifierToken, route(async (req, res) => {
  const { statut } = req.body
  if (!validStatut(statut)) return res.status(400).json({ message: 'Statut invalide' })
  await pool.query('UPDATE admpcs.processus SET statut = $1 WHERE pcs_id = $2', [statut, req.params.id])
  const pcs = await pool.query('SELECT * FROM admpcs.processus WHERE pcs_id = $1', [req.params.id])
  res.json(pcs.rows[0])
}))

app.delete('/processus/:id', verifierToken, route(async (req, res) => {
  await pool.query('SELECT admpcs.app_del_processus($1)', [req.params.id])
  res.json({ message: 'Supprimé' })
}))

// ============================================================================
// WORKFLOW
// ============================================================================

app.get('/processus/:id/workflows', verifierToken, route(async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM admpcs.workflow WHERE pcs_id = $1 ORDER BY wkfnum', [req.params.id])
  res.json(result.rows)
}))

app.post('/processus/:id/workflows', verifierToken, route(async (req, res) => {
  const { wkfnom, wkfrspgrp } = req.body
  if (!wkfnom || !wkfnom.trim()) return res.status(400).json({ message: 'Nom requis' })
  const r = await pool.query(
    'SELECT admpcs.app_ins_workflow($1, $2, $3, $4) AS wkf_id',
    [req.params.id, null, wkfnom, wkfrspgrp || 'ADMIN']
  )
  const wkf = await pool.query('SELECT * FROM admpcs.workflow WHERE wkf_id = $1', [r.rows[0].wkf_id])
  res.json(wkf.rows[0])
}))

app.put('/workflows/:id', verifierToken, route(async (req, res) => {
  const { wkfnom, wkfrspgrp, wkfistuni } = req.body
  const w = await pool.query('SELECT pcs_id FROM admpcs.workflow WHERE wkf_id = $1', [req.params.id])
  await pool.query('SELECT admpcs.app_upd_workflow($1, $2, $3, $4, $5)',
    [w.rows[0].pcs_id, req.params.id, wkfnom, wkfrspgrp || 'ADMIN', wkfistuni ?? 0])
  const wkf = await pool.query('SELECT * FROM admpcs.workflow WHERE wkf_id = $1', [req.params.id])
  res.json(wkf.rows[0])
}))

app.patch('/workflows/:id/statut', verifierToken, route(async (req, res) => {
  const { statut } = req.body
  if (!validStatut(statut)) return res.status(400).json({ message: 'Statut invalide' })
  await pool.query('UPDATE admpcs.workflow SET statut = $1 WHERE wkf_id = $2', [statut, req.params.id])
  const wkf = await pool.query('SELECT * FROM admpcs.workflow WHERE wkf_id = $1', [req.params.id])
  res.json(wkf.rows[0])
}))

app.delete('/workflows/:id', verifierToken, route(async (req, res) => {
  const w = await pool.query('SELECT pcs_id FROM admpcs.workflow WHERE wkf_id = $1', [req.params.id])
  await pool.query('SELECT admpcs.app_del_workflow($1, $2)', [w.rows[0].pcs_id, req.params.id])
  res.json({ message: 'Supprimé' })
}))

// ============================================================================
// ACTIVITES
// ============================================================================

app.get('/workflows/:id/activites', verifierToken, route(async (req, res) => {
  const result = await pool.query(
    `SELECT pa.* FROM admpcs.processus_activite pa
     JOIN admpcs.workflow_activite wa ON wa.act_id = pa.act_id
     WHERE wa.wkf_id = $1 ORDER BY pa.actnumord`, [req.params.id])
  res.json(result.rows)
}))

app.post('/workflows/:id/activites', verifierToken, route(async (req, res) => {
  const { actnom, actnumord, pcsjal } = req.body
  if (!actnom || !actnom.trim()) return res.status(400).json({ message: 'Nom requis' })
  const w = await pool.query('SELECT pcs_id FROM admpcs.workflow WHERE wkf_id = $1', [req.params.id])
  const pcs_id = w.rows[0].pcs_id
  const ord = await pool.query(
    'SELECT COALESCE(MAX(actnumord), 0) + 1 AS next FROM admpcs.processus_activite WHERE pcs_id = $1', [pcs_id])
  const num = actnumord || ord.rows[0].next
  const r = await pool.query(
    `SELECT * FROM admpcs.app_ins_activite($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
    [pcs_id, req.params.id, 1, num, actnom, null, null, null, null, null, null, pcsjal || null, null]
  )
  const act = await pool.query('SELECT * FROM admpcs.processus_activite WHERE act_id = $1', [r.rows[0].p_act_id])
  res.json(act.rows[0])
}))

app.put('/activites/:id', verifierToken, route(async (req, res) => {
  const { actnom, actnumord, pcsjal, wkfactacv, wkfactdsc, wkfactrspgrp, wkfactitvgrp, wkfactdel, wkfactdeluni } = req.body
  const pa = await pool.query('SELECT * FROM admpcs.processus_activite WHERE act_id = $1', [req.params.id])
  const wa = await pool.query('SELECT * FROM admpcs.workflow_activite WHERE act_id = $1 LIMIT 1', [req.params.id])
  const pcs_id = pa.rows[0].pcs_id
  const wkf_id = wa.rows[0].wkf_id
  await pool.query(
    `SELECT admpcs.app_upd_activite($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
    [pcs_id, wkf_id, req.params.id, wkfactacv ?? 1, actnumord || pa.rows[0].actnumord,
     actnom, null, wkfactdsc || null, wkfactrspgrp || null, wkfactitvgrp || null,
     wkfactdel || null, wkfactdeluni || null, pcsjal || null, null]
  )
  const act = await pool.query('SELECT * FROM admpcs.processus_activite WHERE act_id = $1', [req.params.id])
  res.json(act.rows[0])
}))

app.patch('/activites/:id/statut', verifierToken, route(async (req, res) => {
  const { statut } = req.body
  if (!validStatut(statut)) return res.status(400).json({ message: 'Statut invalide' })
  await pool.query('UPDATE admpcs.processus_activite SET statut = $1 WHERE act_id = $2', [statut, req.params.id])
  const act = await pool.query('SELECT * FROM admpcs.processus_activite WHERE act_id = $1', [req.params.id])
  res.json(act.rows[0])
}))

// Réordonnement — reçoit une liste d'ids dans le nouvel ordre et met à jour actnumord
app.patch('/workflows/:id/activites/ordre', verifierToken, route(async (req, res) => {
  const { ordre } = req.body // ex: [act_id_3, act_id_1, act_id_2]
  if (!Array.isArray(ordre)) return res.status(400).json({ message: 'Liste ordre requise' })
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    for (let i = 0; i < ordre.length; i++) {
      await client.query('UPDATE admpcs.processus_activite SET actnumord = $1 WHERE act_id = $2', [i + 1, ordre[i]])
    }
    await client.query('COMMIT')
    res.json({ message: 'Ordre mis à jour' })
  } catch (e) {
    await client.query('ROLLBACK')
    throw e
  } finally {
    client.release()
  }
}))

app.delete('/activites/:id', verifierToken, route(async (req, res) => {
  const pa = await pool.query('SELECT pcs_id FROM admpcs.processus_activite WHERE act_id = $1', [req.params.id])
  const wa = await pool.query('SELECT wkf_id FROM admpcs.workflow_activite WHERE act_id = $1 LIMIT 1', [req.params.id])
  await pool.query('SELECT admpcs.app_del_activite($1, $2, $3)',
    [pa.rows[0].pcs_id, wa.rows[0].wkf_id, req.params.id])
  res.json({ message: 'Supprimé' })
}))

// ============================================================================
// WORKFLOW_INFO
// ============================================================================

app.get('/workflows/:id/infos', verifierToken, route(async (req, res) => {
  const result = await pool.query('SELECT * FROM admpcs.workflow_info WHERE wkf_id = $1', [req.params.id])
  res.json(result.rows)
}))

app.post('/workflows/:id/infos', verifierToken, route(async (req, res) => {
  const { wkfinfnom, wkfinftyp, wkfinfval, wkfinfmlt } = req.body
  const w = await pool.query('SELECT pcs_id FROM admpcs.workflow WHERE wkf_id = $1', [req.params.id])
  const r = await pool.query(
    'SELECT admpcs.app_ins_workflow_info($1, $2, $3, $4, $5, $6) AS wkfinf_id',
    [w.rows[0].pcs_id, req.params.id, wkfinfnom, wkfinftyp, wkfinfval || null, wkfinfmlt ?? 0]
  )
  const info = await pool.query('SELECT * FROM admpcs.workflow_info WHERE wkfinf_id = $1', [r.rows[0].wkfinf_id])
  res.json(info.rows[0])
}))

app.delete('/infos/:id', verifierToken, route(async (req, res) => {
  const info = await pool.query('SELECT wkf_id FROM admpcs.workflow_info WHERE wkfinf_id = $1', [req.params.id])
  const w = await pool.query('SELECT pcs_id FROM admpcs.workflow WHERE wkf_id = $1', [info.rows[0].wkf_id])
  await pool.query('SELECT admpcs.app_del_workflow_info($1, $2, $3)',
    [w.rows[0].pcs_id, info.rows[0].wkf_id, req.params.id])
  res.json({ message: 'Supprimé' })
}))

// ============================================================================
// SOUS_PROCESSUS
// ============================================================================

app.get('/processus/:id/sous-processus', verifierToken, route(async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM admpcs.sous_processus WHERE pcs_id = $1 ORDER BY soupcsnum', [req.params.id])
  res.json(result.rows)
}))

app.post('/processus/:id/sous-processus', verifierToken, route(async (req, res) => {
  const { soupcsnom, soupcsdel, soupcsdeluni, soupcsfml } = req.body
  const r = await pool.query(
    'SELECT admpcs.app_ins_sous_processus($1, $2, $3, $4, $5) AS soupcs_id',
    [req.params.id, soupcsnom, soupcsdel || null, soupcsdeluni || null, soupcsfml || null]
  )
  const sp = await pool.query('SELECT * FROM admpcs.sous_processus WHERE soupcs_id = $1', [r.rows[0].soupcs_id])
  res.json(sp.rows[0])
}))

app.delete('/sous-processus/:id', verifierToken, route(async (req, res) => {
  const sp = await pool.query('SELECT pcs_id FROM admpcs.sous_processus WHERE soupcs_id = $1', [req.params.id])
  await pool.query('SELECT admpcs.app_del_sous_processus($1, $2)', [sp.rows[0].pcs_id, req.params.id])
  res.json({ message: 'Supprimé' })
}))

// ============================================================================
// CONTRAINTES
// ============================================================================

app.post('/contraintes', verifierToken, route(async (req, res) => {
  const { maiwkfact_id, filwkfact_id, lietyp, wkfactctracv, wkfactctrdel, wkfactctrdeluni } = req.body
  const wa = await pool.query('SELECT wkf_id FROM admpcs.workflow_activite WHERE wkfact_id = $1', [maiwkfact_id])
  const w = await pool.query('SELECT pcs_id FROM admpcs.workflow WHERE wkf_id = $1', [wa.rows[0].wkf_id])
  const r = await pool.query(
    'SELECT admpcs.app_ins_act_contrainte($1, $2, $3, $4, $5, $6, $7, $8) AS actctr_id',
    [w.rows[0].pcs_id, wa.rows[0].wkf_id, maiwkfact_id, filwkfact_id,
     lietyp || 'FD', wkfactctracv ?? 1, wkfactctrdel ?? 0, wkfactctrdeluni || 'JOU']
  )
  res.json({ actctr_id: r.rows[0].actctr_id })
}))

app.delete('/contraintes/:id', verifierToken, route(async (req, res) => {
  await pool.query('SELECT admpcs.app_del_act_contrainte($1)', [req.params.id])
  res.json({ message: 'Supprimé' })
}))

// ============================================================================
// 404 + LISTEN
// ============================================================================

app.use((req, res) => res.status(404).json({ message: 'Route introuvable' }))

app.listen(process.env.PORT, () => {
  console.log(`Serveur PCS démarré sur http://localhost:${process.env.PORT}`)
})