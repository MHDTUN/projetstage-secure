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
  max: 100,
  validate: { xForwardedForHeader: false }
})
app.use(limiter)

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false }
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  const result = await pool.query(
    'SELECT * FROM admpcs.utilisateurs WHERE username = $1', [username]
  )
  const user = result.rows[0]
  if (!user) return res.status(401).json({ message: 'Identifiants incorrects' })
  const valide = await bcrypt.compare(password, user.password)
  if (!valide) return res.status(401).json({ message: 'Identifiants incorrects' })
  const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' })
  res.json({ token })
})

app.post('/inscription', async (req, res) => {
  const { username, password } = req.body
  const hash = await bcrypt.hash(password, 10)
  await pool.query(
    'INSERT INTO admpcs.utilisateurs (username, password) VALUES ($1, $2)',
    [username, hash]
  )
  res.json({ message: 'Compte créé' })
})

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

// PROCESSUS
app.get('/processus', verifierToken, async (req, res) => {
  const result = await pool.query('SELECT * FROM admpcs.processus')
  res.json(result.rows)
})

app.post('/processus', verifierToken, async (req, res) => {
  const { pcsnom, pcsrspgrp } = req.body
  const nextId = await pool.query("SELECT nextval('admpcs.seq_processus') as id")
  const id = parseInt(nextId.rows[0].id)
  const pcsnum = 'PCS-' + id
  const result = await pool.query(
    `INSERT INTO admpcs.processus (pcs_id, pcsnum, pcsnumcrt, pcsnom, pcsstu, pcsrspgrp)
     VALUES ($1, $2, $1, $3, 'ACT', $4) RETURNING *`,
    [id, pcsnum, pcsnom, pcsrspgrp]
  )
  res.json(result.rows[0])
})

app.put('/processus/:id', verifierToken, async (req, res) => {
  const { pcsnom } = req.body
  const result = await pool.query(
    'UPDATE admpcs.processus SET pcsnom = $1 WHERE pcs_id = $2 RETURNING *',
    [pcsnom, req.params.id]
  )
  res.json(result.rows[0])
})

app.delete('/processus/:id', verifierToken, async (req, res) => {
  await pool.query('DELETE FROM admpcs.processus WHERE pcs_id = $1', [req.params.id])
  res.json({ message: 'Supprimé' })
})

// WORKFLOWS
app.get('/processus/:id/workflows', verifierToken, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM admpcs.workflow WHERE pcs_id = $1', [req.params.id]
  )
  res.json(result.rows)
})

app.post('/processus/:id/workflows', verifierToken, async (req, res) => {
  const { wkfnom } = req.body
  const nextId = await pool.query("SELECT nextval('admpcs.seq_workflow') as id")
  const id = parseInt(nextId.rows[0].id)
  const wkfnum = 'WKF-' + id
  const result = await pool.query(
    `INSERT INTO admpcs.workflow (wkf_id, pcs_id, wkfnum, wkfnumcrt, wkfnom, wkfrspgrp)
     VALUES ($1, $2, $3, $1, $4, 'ADMIN') RETURNING *`,
    [id, req.params.id, wkfnum, wkfnom]
  )
  res.json(result.rows[0])
})

app.put('/workflows/:id', verifierToken, async (req, res) => {
  const { wkfnom } = req.body
  const result = await pool.query(
    'UPDATE admpcs.workflow SET wkfnom = $1 WHERE wkf_id = $2 RETURNING *',
    [wkfnom, req.params.id]
  )
  res.json(result.rows[0])
})

app.delete('/workflows/:id', verifierToken, async (req, res) => {
  await pool.query('DELETE FROM admpcs.workflow_activite WHERE wkf_id = $1', [req.params.id])
  await pool.query('DELETE FROM admpcs.workflow WHERE wkf_id = $1', [req.params.id])
  res.json({ message: 'Supprimé' })
})

// ACTIVITES
app.get('/workflows/:id/activites', verifierToken, async (req, res) => {
  const result = await pool.query(
    `SELECT pa.* FROM admpcs.processus_activite pa
     JOIN admpcs.workflow_activite wa ON wa.act_id = pa.act_id
     WHERE wa.wkf_id = $1`,
    [req.params.id]
  )
  res.json(result.rows)
})

app.post('/workflows/:id/activites', verifierToken, async (req, res) => {
  const { actnom } = req.body
  const nextId = await pool.query("SELECT nextval('admpcs.seq_processus_activite') as id")
  const actId = parseInt(nextId.rows[0].id)
  const actnum = 'ACT-' + actId

  const pcsResult = await pool.query(
    'SELECT pcs_id FROM admpcs.workflow WHERE wkf_id = $1', [req.params.id]
  )
  const pcsId = pcsResult.rows[0].pcs_id

  const numord = await pool.query(
    'SELECT COALESCE(MAX(actnumord), 0) + 1 as next FROM admpcs.processus_activite WHERE pcs_id = $1',
    [pcsId]
  )

  await pool.query(
    `INSERT INTO admpcs.processus_activite (pcs_id, act_id, actnum, actnumcrt, actnom, actnumord)
     VALUES ($1, $2, $3, $2, $4, $5)`,
    [pcsId, actId, actnum, actnom, numord.rows[0].next]
  )

  const nextWkfActId = await pool.query("SELECT nextval('admpcs.seq_workflow_activite') as id")
  const wkfActId = parseInt(nextWkfActId.rows[0].id)

  await pool.query(
    `INSERT INTO admpcs.workflow_activite (wkfact_id, wkf_id, act_id, wkfactnum, wkfactnumcrt, wkfactacv, wkfactrspgrp)
     VALUES ($1, $2, $3, $4, $3, 1, 'ADMIN')`,
    [wkfActId, req.params.id, actId, actnum]
  )

  const result = await pool.query(
    'SELECT * FROM admpcs.processus_activite WHERE act_id = $1', [actId]
  )
  res.json(result.rows[0])
})

app.put('/activites/:id', verifierToken, async (req, res) => {
  const { actnom } = req.body
  const result = await pool.query(
    'UPDATE admpcs.processus_activite SET actnom = $1 WHERE act_id = $2 RETURNING *',
    [actnom, req.params.id]
  )
  res.json(result.rows[0])
})

app.delete('/activites/:id', verifierToken, async (req, res) => {
  await pool.query('DELETE FROM admpcs.workflow_activite WHERE act_id = $1', [req.params.id])
  await pool.query('DELETE FROM admpcs.processus_activite WHERE act_id = $1', [req.params.id])
  res.json({ message: 'Supprimé' })
})

app.listen(process.env.PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${process.env.PORT}`)
})