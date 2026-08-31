import 'dotenv/config'
import bcrypt from 'bcryptjs'
import fs from 'fs'
import pg from 'pg'
import { seedUsers } from './users.js'

const { Client } = pg
const databaseUrl = process.env.DATABASE_URL
const applicationTables = [
  'app_settings',
  'users',
  'events',
  'ticket_types',
  'purchases',
  'purchase_items',
  'audit_logs',
]

if (!databaseUrl) {
  throw new Error('DATABASE_URL is required')
}

const client = new Client({
  connectionString: databaseUrl,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false,
})

try {
  await client.connect()
  await client.query('BEGIN')

  const existingTablesResult = await client.query(
    `
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = 'public'
      AND table_name = ANY($1::text[])
    ORDER BY table_name
    `,
    [applicationTables]
  )

  if (existingTablesResult.rows.length > 0) {
    const existingTables = existingTablesResult.rows
      .map((row) => row.table_name)
      .join(', ')

    throw new Error(
      `Database initialization stopped because application tables already exist: ${existingTables}`
    )
  }

  const schema = fs.readFileSync(new URL('./schema.sql', import.meta.url), 'utf8')
  await client.query(schema)

  for (const user of seedUsers) {
    const passwordHash = await bcrypt.hash(user.password, 10)

    await client.query(
      `
      INSERT INTO users (email, password_hash, wallet_balance, is_admin)
      VALUES ($1, $2, $3, $4)
      `,
      [user.email, passwordHash, user.walletBalance ?? 5, user.isAdmin]
    )
  }

  const events = [
    [1, 'SeatGate X Trial', 'Audit Control Theatre', 'Friday, Apr 25, 2026', 'seatgate-trial.png'],
    [2, 'SeatGate X Main', 'Revenue Recognition Hall', 'Friday, Apr 25, 2026', 'seatgate-main.png'],
  ]

  for (const event of events) {
    await client.query(
      `
      INSERT INTO events (id, title, venue, event_date, image)
      VALUES ($1, $2, $3, $4, $5)
      `,
      event
    )
  }

  for (const event of events) {
    const eventId = event[0]
    const price = eventId === 1 ? 1 : 1
    const releasedQuantity = eventId === 1 ? 99999 : 0
    const ticketName = eventId === 1 ? 'Trial Tickets' : 'Main Tickets'

    await client.query(
      `
      INSERT INTO ticket_types
        (event_id, name, price, total_quantity,
         released_quantity, sold_quantity, is_released)
      VALUES
        ($1, $2, $3, 99999, $4, 0, $5)
      `,
      [eventId, ticketName, price, releasedQuantity, releasedQuantity > 0]
    )
  }

  const fakePurchaseResult = await client.query(
    `
    INSERT INTO purchases (user_id, event_id, total_amount, status, ip_address, user_agent)
    SELECT id, 2, 20.00, 'SUCCESS', 'seed', 'database initialization'
    FROM users
    WHERE email = 'fakebuyer'
    RETURNING id
    `
  )

  const fakePurchase = fakePurchaseResult.rows[0]

  if (!fakePurchase) {
    throw new Error('The fake buyer was not found in seedUsers')
  }

  await client.query(
    `
    INSERT INTO purchase_items (purchase_id, ticket_type_id, quantity, unit_price)
    SELECT $1, id, 20, price
    FROM ticket_types
    WHERE event_id = 2
      AND name = 'Main Tickets'
    `,
    [fakePurchase.id]
  )

  await client.query(
    `
    UPDATE ticket_types
    SET sold_quantity = sold_quantity + 20
    WHERE event_id = 2
      AND name = 'Main Tickets'
    `
  )

  await client.query(
    `
    INSERT INTO audit_logs (user_id, action, success, metadata)
    VALUES (NULL, 'INITIALIZE_DATABASE', TRUE, $1)
    `,
    [{ source: 'github-actions' }]
  )

  await client.query('COMMIT')
  console.log('Database initialized successfully.')
} catch (error) {
  await client.query('ROLLBACK').catch(() => {})
  console.error(error.message)
  process.exitCode = 1
} finally {
  await client.end().catch(() => {})
}
