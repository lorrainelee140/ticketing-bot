import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import bcrypt from 'bcryptjs'
import crypto from 'crypto'
import { query, getClient } from './db.js'
import { seedUsers } from './users.js'
import fs from 'fs'

import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()

app.set('trust proxy', true)

app.use(cors({
  origin: 'https://lorrainelee140.github.io',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}))

app.use(express.json())

const distPath = path.join(__dirname, '../dist')
const indexPath = path.join(distPath, 'index.html')
const hasBuiltFrontend = fs.existsSync(indexPath)

if (hasBuiltFrontend) {
  app.use(express.static(distPath))
}

const PORT = process.env.PORT || 10000
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-this'
const DEFAULT_TICKET_LIMIT_PER_TYPE = 3
const TICKET_LIMIT_SETTING_KEY = 'ticket_limit_per_type'
let settingsTableReady = null

function parsePositiveInteger(value) {
  const numericValue = Number(value)
  return Number.isInteger(numericValue) && numericValue > 0 ? numericValue : null
}

function ensureSettingsTable() {
  if (!settingsTableReady) {
    settingsTableReady = query(`
      CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `)
      .then(() =>
        query(
          `
            INSERT INTO app_settings (key, value)
            VALUES ($1, $2)
            ON CONFLICT (key) DO NOTHING
          `,
          [TICKET_LIMIT_SETTING_KEY, String(DEFAULT_TICKET_LIMIT_PER_TYPE)]
        )
      )
      .catch((error) => {
        settingsTableReady = null
        throw error
      })
  }

  return settingsTableReady
}

async function getTicketLimit() {
  await ensureSettingsTable()
  const result = await query('SELECT value FROM app_settings WHERE key = $1', [
    TICKET_LIMIT_SETTING_KEY,
  ])
  return parsePositiveInteger(result.rows[0]?.value) || DEFAULT_TICKET_LIMIT_PER_TYPE
}

async function setTicketLimit(limit) {
  await ensureSettingsTable()
  const result = await query(
    `
      INSERT INTO app_settings (key, value, updated_at)
      VALUES ($1, $2, NOW())
      ON CONFLICT (key)
      DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
      RETURNING value, updated_at
    `,
    [TICKET_LIMIT_SETTING_KEY, String(limit)]
  )

  return {
    limit: Number(result.rows[0].value),
    updatedAt: result.rows[0].updated_at,
  }
}

function asyncHandler(handler) {
  return function wrappedAsyncHandler(req, res, next) {
    Promise.resolve(handler(req, res, next)).catch(next)
  }
}

// In-memory rate-limit store.
// Good enough for a classroom sandbox on one Render instance.
const rateLimitStore = new Map()

function rateLimit({
  keyPrefix,
  maxRequests = 2,
  windowMs = 1000,
  getKey,
}) {
  return async function rateLimitMiddleware(req, res, next) {
    const key = `${keyPrefix}:${getKey(req)}`
    const now = Date.now()

    const existing = rateLimitStore.get(key) || []
    const recent = existing.filter((timestamp) => now - timestamp < windowMs)

    if (recent.length >= maxRequests) {
      await writeAuditLog({
        userId: req.user?.id || null,
        action: 'RATE_LIMIT_BLOCKED',
        success: false,
        metadata: {
          path: req.path,
          method: req.method,
          key,
          maxRequests,
          windowMs,
          recentCount: recent.length,
        },
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      })

      return res.status(429).json({
        error: 'Too many requests. Please slow down.',
        retryAfterSeconds: Math.ceil(windowMs / 1000),
      })
    }

    recent.push(now)
    rateLimitStore.set(key, recent)

    next()
  }
}

function createToken(user) {
  const data = `${user.id}:${user.is_admin ? 1 : 0}`
  const hmac = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('hex').slice(0, 10)
  return `${data}:${hmac}`
}

function getBearerToken(req) {
  const header = req.headers.authorization || ''
  return header.startsWith('Bearer ') ? header.slice(7) : null
}

function parseAuthToken(token) {
  const [id, isAdmin, hmac] = token.split(':')
  const expectedHmac = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${id}:${isAdmin}`)
    .digest('hex')
    .slice(0, 10)

  if (!id || !isAdmin || hmac !== expectedHmac) {
    throw new Error('Invalid token')
  }

  return {
    id: parseInt(id, 10),
    isAdmin: isAdmin === '1',
  }
}

function authRequired(req, res, next) {
  const token = getBearerToken(req)

  if (!token) {
    return res.status(401).json({ error: 'Missing token' })
  }

  try {
    req.user = parseAuthToken(token)
    next()
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' })
  }
}

const userTwoPerSecond = rateLimit({
  keyPrefix: 'user',
  maxRequests: 5,
  windowMs: 1000,
  getKey: (req) => req.user?.id || req.ip,
})

function adminRequired(req, res, next) {
  if (!req.user?.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' })
  }

  next()
}

app.get('/api/my-holdings', authRequired, userTwoPerSecond, asyncHandler(async (req, res) => {
  const userResult = await query(
    `
    SELECT id, email, wallet_balance
    FROM users
    WHERE id = $1
    `,
    [req.user.id]
  )

  const user = userResult.rows[0]

  if (!user) {
    return res.status(404).json({ error: 'User not found' })
  }

  const holdingsResult = await query(
    `
    SELECT
      purchases.id AS purchase_id,
      purchases.created_at,
      events.id AS event_id,
      events.title AS event_title,
      events.venue AS event_venue,
      events.event_date,
      ticket_types.name AS ticket_type,
      purchase_items.quantity,
      purchase_items.unit_price,
      purchase_items.quantity * purchase_items.unit_price AS subtotal
    FROM purchases
    JOIN purchase_items
      ON purchase_items.purchase_id = purchases.id
    JOIN ticket_types
      ON ticket_types.id = purchase_items.ticket_type_id
    JOIN events
      ON events.id = purchases.event_id
    WHERE purchases.user_id = $1
      AND purchases.status = 'SUCCESS'
    ORDER BY purchases.created_at DESC
    `,
    [req.user.id]
  )

  res.json({
    user: {
      id: user.id,
      email: user.email,
      walletBalance: Number(user.wallet_balance),
    },
    holdings: holdingsResult.rows.map((row) => ({
      purchaseId: row.purchase_id,
      createdAt: row.created_at,
      eventId: row.event_id,
      eventTitle: row.event_title,
      eventVenue: row.event_venue,
      eventDate: row.event_date,
      ticketType: row.ticket_type,
      quantity: Number(row.quantity),
      unitPrice: Number(row.unit_price),
      subtotal: Number(row.subtotal),
    })),
  })
}))

async function writeAuditLog({
  userId = null,
  action,
  eventId = null,
  ticketTypeId = null,
  success,
  metadata = {},
  ip = null,
  userAgent = null,
}, queryExecutor = query) {
  await queryExecutor(
    `
    INSERT INTO audit_logs
      (user_id, action, event_id, ticket_type_id, success, metadata, ip_address, user_agent)
    VALUES
      ($1, $2, $3, $4, $5, $6, $7, $8)
    `,
    [userId, action, eventId, ticketTypeId, success, metadata, ip, userAgent]
  )
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'acc3202-ticketing-api' })
})

app.get('/api/health/db', asyncHandler(async (req, res) => {
  const result = await query('SELECT NOW() AS now')

  res.json({
    ok: true,
    service: 'acc3202-ticketing-api',
    database: true,
    now: result.rows[0].now,
  })
}))

app.post('/api/login', asyncHandler(async (req, res) => {
  const username = req.body.username ?? req.body.email
  const { password } = req.body

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' })
  }

  const result = await query(
    `
    SELECT id, email, password_hash, wallet_balance, is_admin
    FROM users
    WHERE LOWER(email) = LOWER($1)
    `,
    [username]
  )

  const user = result.rows[0]

  if (!user) {
    await writeAuditLog({
      action: 'LOGIN_FAILED',
      success: false,
      metadata: { username, reason: 'unknown_username' },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    })

    return res.status(401).json({ error: 'Invalid username or password' })
  }

  const ok = await bcrypt.compare(password, user.password_hash)

  if (!ok) {
    await writeAuditLog({
      userId: user.id,
      action: 'LOGIN_FAILED',
      success: false,
      metadata: { username, reason: 'bad_password' },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    })

    return res.status(401).json({ error: 'Invalid username or password' })
  }

  await writeAuditLog({
    userId: user.id,
    action: 'LOGIN_SUCCESS',
    success: true,
    metadata: { username },
    ip: req.ip,
    userAgent: req.headers['user-agent'],
  })

  const token = createToken(user)

  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      walletBalance: Number(user.wallet_balance),
      isAdmin: user.is_admin,
    },
  })
}))

app.get('/api/me', authRequired, userTwoPerSecond, asyncHandler(async (req, res) => {
  const result = await query(
    `
    SELECT id, email, wallet_balance, is_admin
    FROM users
    WHERE id = $1
    `,
    [req.user.id]
  )

  const user = result.rows[0]

  if (!user) {
    return res.status(404).json({ error: 'User not found' })
  }

  res.json({
    id: user.id,
    email: user.email,
    walletBalance: Number(user.wallet_balance),
    isAdmin: user.is_admin,
  })
}))

app.get('/api/admin/automated-buy/access', authRequired, adminRequired, (req, res) => {
  res.json({ ok: true })
})

app.get('/api/admin/ticket-limit', authRequired, adminRequired, asyncHandler(async (req, res) => {
  const limit = await getTicketLimit()
  res.json({ limit })
}))

app.post('/api/admin/ticket-limit', authRequired, adminRequired, asyncHandler(async (req, res) => {
  const limit = parsePositiveInteger(req.body?.limit)

  if (!limit) {
    return res.status(400).json({ error: 'Ticket limit must be a whole number greater than 0' })
  }

  const setting = await setTicketLimit(limit)

  await writeAuditLog({
    userId: req.user.id,
    action: 'ADMIN_UPDATE_TICKET_LIMIT',
    success: true,
    metadata: { limit },
    ip: req.ip,
    userAgent: req.headers['user-agent'],
  })

  res.json({
    success: true,
    limit: setting.limit,
    updatedAt: setting.updatedAt,
  })
}))

app.post('/api/admin/increase-wallets', authRequired, adminRequired, asyncHandler(async (req, res) => {
  const amount = Number(req.body?.amount)

  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Amount must be greater than 0' })
  }

  const normalizedAmount = Number(amount.toFixed(2))
  const result = await query(
    `
    UPDATE users
    SET wallet_balance = wallet_balance + $1
    RETURNING id
    `,
    [normalizedAmount]
  )

  await writeAuditLog({
    userId: req.user.id,
    action: 'ADMIN_INCREASE_ALL_WALLETS',
    success: true,
    metadata: {
      amount: normalizedAmount,
      usersUpdated: result.rowCount,
    },
    ip: req.ip,
    userAgent: req.headers['user-agent'],
  })

  res.json({
    success: true,
    amount: normalizedAmount,
    usersUpdated: result.rowCount,
  })
}))

app.get('/api/events/:eventId/tickets', asyncHandler(async (req, res) => {
  const eventId = Number(req.params.eventId)

  const eventResult = await query(
    `
    SELECT id, title, venue, event_date, image
    FROM events
    WHERE id = $1
      AND id IN (1, 2)
    `,
    [eventId]
  )

  const event = eventResult.rows[0]

  if (!event) {
    return res.status(404).json({ error: 'Event not found' })
  }

  const ticketResult = await query(
    `
    SELECT
      id,
      event_id,
      name,
      price,
      total_quantity,
      released_quantity,
      sold_quantity,
      is_released,
      updated_at,
      GREATEST(released_quantity - sold_quantity, 0) AS available_quantity
    FROM ticket_types
    WHERE event_id = $1
    ORDER BY
      is_released DESC,
      GREATEST(released_quantity - sold_quantity, 0) DESC,
      price ASC,
      id ASC
    `,
    [eventId]
  )

  const mainTicket = ticketResult.rows[0]

  res.json({
    event,
    tickets: mainTicket ? [mainTicket].map((ticket) => ({
      id: ticket.id,
      eventId: ticket.event_id,
      name: ticket.name,
      price: Number(ticket.price),
      totalQuantity: ticket.total_quantity,
      releasedQuantity: ticket.released_quantity,
      soldQuantity: ticket.sold_quantity,
      availableQuantity: Number(ticket.available_quantity),
      isReleased: ticket.is_released,
      updatedAt: ticket.updated_at,
      soldOut:
        !ticket.is_released || Number(ticket.available_quantity) <= 0,
    })) : [],
  })
}))

app.post('/api/purchase', authRequired, userTwoPerSecond, asyncHandler(async (req, res) => {
  const eventId = Number(req.body.eventId)
  const { items } = req.body

  if (!eventId || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'eventId and items are required' })
  }

  const cleanItems = items
    .map((item) => ({
      ticketTypeId: Number(item.ticketTypeId),
      quantity: Number(item.quantity),
    }))
    .filter(
      (item) =>
        Number.isInteger(item.ticketTypeId) &&
        Number.isInteger(item.quantity) &&
        item.ticketTypeId > 0 &&
        item.quantity > 0
    )

  if (cleanItems.length === 0) {
    return res.status(400).json({ error: 'No valid ticket quantities selected' })
  }

  const client = await getClient()
  const clientQuery = client.query.bind(client)

  try {
    await client.query('BEGIN')

    const userResult = await client.query(
      `
      SELECT id, email, wallet_balance, is_admin
      FROM users
      WHERE id = $1
      FOR UPDATE
      `,
      [req.user.id]
    )

    const user = userResult.rows[0]

    if (!user) {
      throw new Error('User not found')
    }

    await client.query('SELECT pg_advisory_xact_lock($1, $2)', [req.user.id, eventId])

    const requestedQuantityByTicketId = cleanItems.reduce((quantities, item) => {
      const currentQuantity = quantities.get(item.ticketTypeId) || 0
      quantities.set(item.ticketTypeId, currentQuantity + item.quantity)

      return quantities
    }, new Map())
    const ticketIds = Array.from(requestedQuantityByTicketId.keys())

    const ticketResult = await client.query(
      `
      SELECT
        id,
        event_id,
        name,
        price,
        released_quantity,
        sold_quantity,
        is_released
      FROM ticket_types
      WHERE id = ANY($1::int[])
        AND event_id = $2
      FOR UPDATE
      `,
      [ticketIds, eventId]
    )

    const ticketsById = new Map(ticketResult.rows.map((row) => [row.id, row]))

    for (const item of cleanItems) {
      const ticket = ticketsById.get(item.ticketTypeId)

      if (!ticket) {
        await client.query('ROLLBACK')

        await writeAuditLog({
          userId: req.user.id,
          action: 'PURCHASE_FAILED',
          eventId,
          ticketTypeId: item.ticketTypeId,
          success: false,
          metadata: { reason: 'ticket_type_not_found', item },
        }, clientQuery)

        return res.status(400).json({ error: 'Invalid ticket type' })
      }

      if (!ticket.is_released) {
        await client.query('ROLLBACK')

        await writeAuditLog({
          userId: req.user.id,
          action: 'PURCHASE_FAILED',
          eventId,
          ticketTypeId: item.ticketTypeId,
          success: false,
          metadata: { reason: 'ticket_not_released', item },
        }, clientQuery)

        return res.status(400).json({ error: `${ticket.name} has not been released yet` })
      }
    }

    if (!user.is_admin) {
      const ticketLimit = await getTicketLimit()
      const existingTypeQuantityResult = await client.query(
        `
        SELECT
          purchase_items.ticket_type_id,
          COALESCE(SUM(purchase_items.quantity), 0)::int AS quantity_owned
        FROM purchases
        JOIN purchase_items
          ON purchase_items.purchase_id = purchases.id
        WHERE purchases.user_id = $1
          AND purchases.status = 'SUCCESS'
          AND purchase_items.ticket_type_id = ANY($2::int[])
        GROUP BY purchase_items.ticket_type_id
        `,
        [req.user.id, ticketIds]
      )

      const quantityOwnedByTicketId = new Map(
        existingTypeQuantityResult.rows.map((row) => [
          row.ticket_type_id,
          Number(row.quantity_owned || 0),
        ])
      )

      for (const [ticketTypeId, requestedTicketQuantity] of requestedQuantityByTicketId) {
        const quantityOwned = quantityOwnedByTicketId.get(ticketTypeId) || 0
        const remainingAllowed = Math.max(ticketLimit - quantityOwned, 0)

        if (requestedTicketQuantity > remainingAllowed) {
          await client.query('ROLLBACK')

          await writeAuditLog({
            userId: req.user.id,
            action: 'PURCHASE_FAILED',
            eventId,
            ticketTypeId,
            success: false,
            metadata: {
              reason: 'per_ticket_type_limit_exceeded',
              limit: ticketLimit,
              quantityOwned,
              requestedQuantity: requestedTicketQuantity,
              remainingAllowed,
            },
            ip: req.ip,
            userAgent: req.headers['user-agent'],
          }, clientQuery)

          return res.status(400).json({
            error: `Each user is limited to ${ticketLimit} tickets of each ticket type`,
            limit: ticketLimit,
            ticketTypeId,
            quantityOwned,
            remainingAllowed,
          })
        }
      }
    }

    let total = 0

    for (const [ticketTypeId, requestedTicketQuantity] of requestedQuantityByTicketId) {
      const ticket = ticketsById.get(ticketTypeId)
      const available = ticket.released_quantity - ticket.sold_quantity

      if (available < requestedTicketQuantity) {
        await client.query('ROLLBACK')

        await writeAuditLog({
          userId: req.user.id,
          action: 'PURCHASE_FAILED',
          eventId,
          ticketTypeId,
          success: false,
          metadata: {
            reason: 'insufficient_inventory',
            requested: requestedTicketQuantity,
            available,
          },
        }, clientQuery)

        return res.status(400).json({ error: `${ticket.name} is sold out or has insufficient quantity` })
      }

      total += Number(ticket.price) * requestedTicketQuantity
    }

    if (Number(user.wallet_balance) < total) {
      await client.query('ROLLBACK')

      await writeAuditLog({
        userId: req.user.id,
        action: 'PURCHASE_FAILED',
        eventId,
        success: false,
        metadata: {
          reason: 'insufficient_wallet_balance',
          walletBalance: Number(user.wallet_balance),
          total,
        },
      }, clientQuery)

      return res.status(400).json({
        error: 'Insufficient wallet balance',
        walletBalance: Number(user.wallet_balance),
        total,
      })
    }

    const purchaseResult = await client.query(
      `
      INSERT INTO purchases (user_id, event_id, total_amount, status, ip_address, user_agent)
      VALUES ($1, $2, $3, 'SUCCESS', $4, $5)
      RETURNING id, created_at
      `,
      [req.user.id, eventId, total, req.ip, req.headers['user-agent']]
    )

    const purchase = purchaseResult.rows[0]

    for (const item of cleanItems) {
      const ticket = ticketsById.get(item.ticketTypeId)

      await client.query(
        `
        UPDATE ticket_types
        SET sold_quantity = sold_quantity + $1
        WHERE id = $2
        `,
        [item.quantity, item.ticketTypeId]
      )

      await client.query(
        `
        INSERT INTO purchase_items
          (purchase_id, ticket_type_id, quantity, unit_price)
        VALUES
          ($1, $2, $3, $4)
        `,
        [purchase.id, item.ticketTypeId, item.quantity, ticket.price]
      )
    }

    const updatedUserResult = await client.query(
      `
      UPDATE users
      SET wallet_balance = wallet_balance - $1
      WHERE id = $2
      RETURNING wallet_balance
      `,
      [total, req.user.id]
    )

    await writeAuditLog({
      userId: req.user.id,
      action: 'PURCHASE_SUCCESS',
      eventId,
      success: true,
      metadata: {
        purchaseId: purchase.id,
        items: cleanItems,
        total,
      },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    }, clientQuery)

    await client.query('COMMIT')

    res.json({
      success: true,
      purchaseId: purchase.id,
      total,
      createdAt: purchase.created_at,
      walletBalance: Number(updatedUserResult.rows[0].wallet_balance),
    })
  } catch (error) {
    await client.query('ROLLBACK')

    await writeAuditLog({
      userId: req.user?.id || null,
      action: 'PURCHASE_ERROR',
      eventId,
      success: false,
      metadata: { error: error.message },
    }, clientQuery)

    res.status(500).json({ error: 'Purchase failed unexpectedly' })
  } finally {
    client.release()
  }
}))

app.post('/api/admin/release-more', authRequired, adminRequired, asyncHandler(async (req, res) => {
  const { ticketTypeId, additionalQuantity } = req.body

  if (!ticketTypeId || additionalQuantity === undefined) {
    return res.status(400).json({
      error: 'ticketTypeId and additionalQuantity are required',
    })
  }

  const result = await query(
    `
    UPDATE ticket_types
    SET
      released_quantity = LEAST(GREATEST(released_quantity, sold_quantity) + $1, total_quantity),
      is_released = TRUE
    WHERE id = $2
    RETURNING
      id,
      event_id,
      name,
      price,
      total_quantity,
      released_quantity,
      sold_quantity,
      GREATEST(released_quantity - sold_quantity, 0) AS available_quantity,
      is_released
    `,
    [Number(additionalQuantity), Number(ticketTypeId)]
  )

  const ticket = result.rows[0]

  if (!ticket) {
    return res.status(404).json({ error: 'Ticket type not found' })
  }

  await writeAuditLog({
    userId: req.user.id,
    action: 'ADMIN_RELEASE_MORE_TICKETS',
    eventId: ticket.event_id,
    ticketTypeId: ticket.id,
    success: true,
    metadata: {
      additionalQuantity: Number(additionalQuantity),
      releasedQuantity: Number(ticket.released_quantity),
      availableQuantity: Number(ticket.available_quantity),
    },
    ip: req.ip,
    userAgent: req.headers['user-agent'],
  })

  res.json({
    success: true,
    ticket: {
      id: ticket.id,
      eventId: ticket.event_id,
      name: ticket.name,
      price: Number(ticket.price),
      totalQuantity: Number(ticket.total_quantity),
      releasedQuantity: Number(ticket.released_quantity),
      soldQuantity: Number(ticket.sold_quantity),
      availableQuantity: Number(ticket.available_quantity),
      isReleased: ticket.is_released,
    },
  })
}))

app.get('/api/admin/holdings', authRequired, adminRequired, asyncHandler(async (req, res) => {
  const result = await query(
    `
    SELECT
      users.id AS user_id,
      users.email,
      users.wallet_balance,
      users.is_admin,
      events.title AS event_title,
      ticket_types.name AS ticket_type,
      SUM(purchase_items.quantity) AS quantity_owned,
      MAX(purchases.created_at) AS last_purchase_at
    FROM users
    LEFT JOIN purchases
      ON purchases.user_id = users.id
      AND purchases.status = 'SUCCESS'
    LEFT JOIN purchase_items
      ON purchase_items.purchase_id = purchases.id
    LEFT JOIN ticket_types
      ON ticket_types.id = purchase_items.ticket_type_id
    LEFT JOIN events
      ON events.id = purchases.event_id
    GROUP BY
      users.id,
      users.email,
      users.wallet_balance,
      users.is_admin,
      events.title,
      ticket_types.name
    ORDER BY
      users.email,
      events.title,
      ticket_types.name
    `
  )

  res.json(result.rows)
}))

app.get('/api/admin/max-ticket-buyers', authRequired, adminRequired, asyncHandler(async (req, res) => {
  const ticketLimit = await getTicketLimit()
  const result = await query(
    `
    WITH purchase_events AS (
      SELECT
        users.id AS user_id,
        users.email,
        purchases.id AS purchase_id,
        purchases.event_id,
        events.title AS event_title,
        ticket_types.id AS ticket_type_id,
        ticket_types.name AS ticket_type,
        purchases.created_at,
        SUM(purchase_items.quantity)::int AS purchase_quantity
      FROM purchases
      JOIN users
        ON users.id = purchases.user_id
      JOIN purchase_items
        ON purchase_items.purchase_id = purchases.id
      JOIN ticket_types
        ON ticket_types.id = purchase_items.ticket_type_id
      JOIN events
        ON events.id = purchases.event_id
      WHERE purchases.status = 'SUCCESS'
        AND COALESCE(purchases.ip_address, '') <> 'seed'
        AND users.is_admin = FALSE
      GROUP BY
        users.id,
        users.email,
        purchases.id,
        purchases.event_id,
        events.title,
        ticket_types.id,
        ticket_types.name,
        purchases.created_at
    ),
    cumulative_purchases AS (
      SELECT
        user_id,
        email,
        purchase_id,
        event_id,
        event_title,
        ticket_type_id,
        ticket_type,
        created_at,
        (
          SUM(purchase_quantity) OVER (
            PARTITION BY user_id, ticket_type_id
            ORDER BY created_at ASC, purchase_id ASC
            ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
          )
        )::int AS quantity_owned
      FROM purchase_events
    ),
    first_to_limit AS (
      SELECT DISTINCT ON (user_id, ticket_type_id)
        user_id,
        email,
        event_id,
        event_title,
        ticket_type_id,
        ticket_type,
        quantity_owned,
        created_at AS max_reached_at
      FROM cumulative_purchases
      WHERE quantity_owned >= $1
      ORDER BY user_id, ticket_type_id, created_at ASC, purchase_id ASC
    )
    SELECT
      email,
      event_id,
      event_title,
      ticket_type_id,
      ticket_type,
      quantity_owned,
      max_reached_at,
      $1::int AS max_tickets
    FROM first_to_limit
    ORDER BY
      max_reached_at ASC,
      email ASC,
      event_title ASC,
      ticket_type ASC
    `,
    [ticketLimit]
  )

  res.json(result.rows)
}))

app.get('/api/admin/revenue', authRequired, adminRequired, asyncHandler(async (req, res) => {
  const result = await query(
    `
    SELECT
      users.email,
      events.title AS event_title,
      ticket_types.name AS ticket_type,
      SUM(purchase_items.quantity)::int AS quantity_sold,
      purchase_items.unit_price,
      SUM(purchase_items.quantity * purchase_items.unit_price) AS revenue,
      MAX(purchases.created_at) AS last_purchase_at
    FROM purchases
    JOIN users
      ON users.id = purchases.user_id
    JOIN purchase_items
      ON purchase_items.purchase_id = purchases.id
    JOIN ticket_types
      ON ticket_types.id = purchase_items.ticket_type_id
    JOIN events
      ON events.id = purchases.event_id
    WHERE purchases.status = 'SUCCESS'
      AND users.is_admin = FALSE
    GROUP BY
      users.email,
      events.title,
      ticket_types.name,
      purchase_items.unit_price
    ORDER BY
      events.title,
      users.email,
      ticket_types.name,
      purchase_items.unit_price
    `
  )

  res.json(result.rows)
}))

app.get('/api/admin/audit-logs', authRequired, adminRequired, asyncHandler(async (req, res) => {
  const result = await query(
    `
    SELECT
      audit_logs.id,
      users.email,
      audit_logs.action,
      audit_logs.event_id,
      audit_logs.ticket_type_id,
      audit_logs.success,
      audit_logs.metadata,
      audit_logs.ip_address,
      audit_logs.user_agent,
      audit_logs.created_at
    FROM audit_logs
    LEFT JOIN users ON users.id = audit_logs.user_id
    ORDER BY audit_logs.created_at DESC
    LIMIT 1000
    `
  )

  res.json(result.rows)
}))

app.post('/api/admin/reset-database', authRequired, adminRequired, asyncHandler(async (req, res) => {
  try {
    const schema = fs.readFileSync(new URL('./schema.sql', import.meta.url), 'utf8')
    await query(schema)

    for (const user of seedUsers) {
      const passwordHash = await bcrypt.hash(user.password, 10)

      await query(
        `
        INSERT INTO users (email, password_hash, wallet_balance, is_admin)
        VALUES ($1, $2, $3, $4)
        `,
        [user.email, passwordHash, user.walletBalance ?? 5.0, user.isAdmin]
      )
    }

    const events = [
      [1, 'SeatGate X Trial', 'Audit Control Theatre', 'Friday, Apr 25, 2026', 'seatgate-trial.png'],
      [2, 'SeatGate X Main', 'Revenue Recognition Hall', 'Friday, Apr 25, 2026', 'seatgate-main.png'],
    ]

    for (const event of events) {
      await query(
        `
        INSERT INTO events (id, title, venue, event_date, image)
        VALUES ($1, $2, $3, $4, $5)
        `,
        event
      )
    }

    for (const event of events) {
      const eventId = event[0]
      const price = eventId === 1 ? 0.00 : 1.00
      const releasedQuantity = eventId === 1 ? 99999 : 0
      const ticketName = eventId === 1 ? 'Trial Tickets' : 'Main Tickets'

      await query(
        `
        INSERT INTO ticket_types
        (event_id, name, price, total_quantity, released_quantity, sold_quantity, is_released)
        VALUES
        ($1, $2, $3, 99999, $4, 0, $5)
        `,
        [eventId, ticketName, price, releasedQuantity, releasedQuantity > 0]
      )
    }

    const fakePurchaseResult = await query(
      `
      INSERT INTO purchases (user_id, event_id, total_amount, status, ip_address, user_agent)
      SELECT id, 2, 20.00, 'SUCCESS', 'seed', 'database seed'
      FROM users
      WHERE email = 'fakebuyer'
      RETURNING id
      `
    )

    const fakePurchase = fakePurchaseResult.rows[0]

    await query(
      `
      INSERT INTO purchase_items (purchase_id, ticket_type_id, quantity, unit_price)
      SELECT $1, id, 20, price
      FROM ticket_types
      WHERE event_id = 2
        AND name = 'Main Tickets'
      `,
      [fakePurchase.id]
    )

    await query(
      `
      UPDATE ticket_types
      SET sold_quantity = sold_quantity + 20
      WHERE event_id = 2
        AND name = 'Main Tickets'
      `
    )

    await writeAuditLog({
      userId: null,
      action: 'ADMIN_RESET_DATABASE',
      success: true,
      metadata: {
        requestedBy: 'admin',
        requestedByUserId: req.user.id,
      },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    })

    res.json({ success: true, message: 'Database reset successfully.' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Database reset failed', detail: error.message })
  }
}))

app.get('/api/admin/ticket-types', authRequired, adminRequired, asyncHandler(async (req, res) => {
  const result = await query(
    `
    SELECT
      events.id AS event_id,
      events.title AS event_title,
      ticket_types.id AS ticket_type_id,
      ticket_types.name AS ticket_type,
      ticket_types.price,
      ticket_types.total_quantity,
      ticket_types.released_quantity,
      ticket_types.sold_quantity,
      GREATEST(ticket_types.released_quantity - ticket_types.sold_quantity, 0) AS available_quantity,
      ticket_types.is_released
    FROM ticket_types
    JOIN events
      ON events.id = ticket_types.event_id
    WHERE events.id IN (1, 2)
    ORDER BY
      events.id,
      ticket_types.price,
      ticket_types.id
    `
  )

  res.json(
    result.rows.map((row) => ({
      eventId: row.event_id,
      eventTitle: row.event_title,
      ticketTypeId: row.ticket_type_id,
      ticketType: row.ticket_type,
      price: Number(row.price),
      totalQuantity: Number(row.total_quantity),
      releasedQuantity: Number(row.released_quantity),
      soldQuantity: Number(row.sold_quantity),
      availableQuantity: Number(row.available_quantity),
      isReleased: row.is_released,
    }))
  )
}))

app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API route not found' })
})

if (hasBuiltFrontend) {
  app.get('*', (req, res) => {
    res.sendFile(indexPath)
  })
} else {
  app.get('/', (req, res) => {
    res.json({
      ok: true,
      service: 'acc3202-ticketing-api',
      frontendUrl: 'https://hunternbh.github.io/acc3202-ticketing-bot/',
    })
  })

  app.get('*', (req, res) => {
    res.status(404).json({
      error: 'Frontend build is not deployed on this Render service.',
      frontendUrl: 'https://hunternbh.github.io/acc3202-ticketing-bot/',
    })
  })
}

app.use((error, req, res, next) => {
  console.error(error)

  if (res.headersSent) {
    return next(error)
  }

  const statusCode = Number(error.status || error.statusCode) || 500
  const safeStatusCode = statusCode >= 400 && statusCode < 600 ? statusCode : 500
  const isDatabaseError = Boolean(
    error.isDatabaseError ||
      error.code ||
      error.routine ||
      error.severity ||
      error.stack?.includes('pg-pool')
  )

  res.status(safeStatusCode).json({
    error:
      safeStatusCode >= 500 && isDatabaseError
        ? 'Database request failed. Check DATABASE_URL and whether the database has been seeded.'
        : safeStatusCode >= 500
          ? 'Server request failed.'
          : error.message || 'Request failed.',
  })
})

app.listen(PORT, () => {
  console.log(`Ticketing API running on port ${PORT}`)
})
