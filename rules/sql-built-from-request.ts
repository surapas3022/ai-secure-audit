// Test cases for sql-built-from-request. Run: opengrep scan --test --taint-intrafile rules/
// Written before the rule. Each case is a shape seen in AI-written code or in public examples of SQL injection.
import express from 'express';
import { Controller, Get, Post, Body, Query, Param } from '@nestjs/common';
import { NextRequest } from 'next/server';
import { Prisma, PrismaClient } from '@prisma/client';

const app = express();
const prisma = new PrismaClient();
declare const db: any, pool: any, sequelize: any, models: any, knex: any, connection: any, sql: any;

// --- Express: value from the request put into the SQL text ---

app.post('/login', async (req, res) => {
  // ruleid: sql-built-from-request
  const user = await models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${req.body.password}'`);
  res.json(user);
});

app.get('/search', async (req, res) => {
  const criteria = req.query.q;
  // ruleid: sql-built-from-request
  const rows = await sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%'`);
  res.json(rows);
});

app.get('/users/:id', async (req, res) => {
  // ruleid: sql-built-from-request
  const r = await pool.query('SELECT * FROM users WHERE id = ' + req.params.id);
  res.json(r.rows);
});

app.get('/orders', async (req, res) => {
  const { sort } = req.query;
  const text = `SELECT * FROM orders ORDER BY ${sort}`;
  // ruleid: sql-built-from-request
  const r = await db.query(text);
  res.json(r);
});

app.get('/sqlite', (req, res) => {
  // ruleid: sql-built-from-request
  db.all(`SELECT * FROM notes WHERE owner = '${req.cookies.user}'`, (err: any, rows: any) => res.json(rows));
});

app.post('/mysql', async (req, res) => {
  // ruleid: sql-built-from-request
  const [rows] = await connection.execute("SELECT * FROM t WHERE name = '" + req.body.name + "'");
  res.json(rows);
});

app.get('/knex', async (req, res) => {
  // ruleid: sql-built-from-request
  res.json(await knex.raw(`SELECT * FROM t WHERE id = ${req.query.id}`));
});

app.get('/header', async (req, res) => {
  // ruleid: sql-built-from-request
  res.json(await db.query(`SELECT * FROM t WHERE tenant = '${req.get('x-tenant')}'`));
});

// --- Prisma: the Unsafe raw functions and Prisma.raw take plain strings ---

app.get('/prisma', async (req, res) => {
  // ruleid: sql-built-from-request
  res.json(await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${req.query.email}'`));
});

app.post('/prisma-exec', async (req, res) => {
  // ruleid: sql-built-from-request
  await prisma.$executeRawUnsafe('DELETE FROM "Post" WHERE id = ' + req.body.id);
  res.end();
});

app.get('/prisma-raw', async (req, res) => {
  // ruleid: sql-built-from-request
  res.json(await prisma.$queryRaw`SELECT * FROM t ORDER BY ${Prisma.raw(req.query.sort as string)}`);
});

// --- A helper in the same file that builds the SQL ---

async function findByName(name: string) {
  // ruleid: sql-built-from-request
  return db.query(`SELECT * FROM t WHERE name = '${name}'`);
}
app.get('/by-name', async (req, res) => res.json(await findByName(req.query.name as string)));

// --- NestJS: decorated parameters are request values ---

@Controller('items')
export class ItemsController {
  constructor(private readonly dataSource: any) {}

  @Get()
  find(@Query('q') q: string) {
    // ruleid: sql-built-from-request
    return this.dataSource.query(`SELECT * FROM items WHERE title LIKE '%${q}%'`);
  }

  @Post()
  create(@Body() body: any) {
    // ruleid: sql-built-from-request
    return this.dataSource.query("INSERT INTO items (title) VALUES ('" + body.title + "')");
  }

  @Get(':id')
  one(@Param('id') id: string) {
    // ok: sql-built-from-request
    return this.dataSource.query('SELECT * FROM items WHERE id = $1', [id]);
  }
}

// --- Next.js route handler ---

export async function POST(request: NextRequest) {
  const { email } = await request.json();
  // ruleid: sql-built-from-request
  const rows = await sql.query(`SELECT * FROM users WHERE email = '${email}'`);
  return Response.json(rows);
}

export async function GET(request: NextRequest) {
  const id = request.nextUrl.searchParams.get('id');
  // ruleid: sql-built-from-request
  return Response.json(await db.query('SELECT * FROM t WHERE id = ' + id));
}

// --- Safe: the value is sent apart from the SQL text ---

app.get('/safe1', async (req, res) => {
  // ok: sql-built-from-request
  res.json(await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]));
});

app.get('/safe2', async (req, res) => {
  // ok: sql-built-from-request
  res.json(await sequelize.query('SELECT * FROM t WHERE name = :name', { replacements: { name: req.query.name } }));
});

app.get('/safe3', async (req, res) => {
  // ok: sql-built-from-request
  res.json(await prisma.$queryRaw`SELECT * FROM t WHERE email = ${req.query.email}`);
});

app.get('/safe4', async (req, res) => {
  // ok: sql-built-from-request
  res.json(await prisma.$queryRawUnsafe('SELECT * FROM t WHERE id = $1', req.query.id));
});

app.get('/safe5', async (req, res) => {
  const ids: string[] = req.body.ids;
  const marks = ids.map(() => '?').join(',');
  // ok: sql-built-from-request
  res.json(await db.all(`SELECT * FROM t WHERE id IN (${marks})`, ids));
});

app.get('/safe6', async (req, res) => {
  const limit = Number(req.query.limit);
  // ok: sql-built-from-request
  res.json(await db.query(`SELECT * FROM t LIMIT ${limit}`));
});

app.get('/safe7', async (req, res) => {
  const page = parseInt(req.query.page as string, 10);
  // ok: sql-built-from-request
  res.json(await db.query(`SELECT * FROM t OFFSET ${page * 10}`));
});

app.get('/safe8', async (req, res) => {
  // ok: sql-built-from-request
  res.json(await db.query(`SELECT * FROM t WHERE name = ${connection.escape(req.query.name)}`));
});

const TABLE = 'products';
app.get('/safe9', async (req, res) => {
  // ok: sql-built-from-request
  res.json(await db.query(`SELECT * FROM ${TABLE} WHERE id = $1`, [req.query.id]));
});

// --- Not SQL: request values given to other get/run/exec methods ---

const cache = new Map<string, string>();
app.get('/not-sql', (req, res) => {
  // ok: sql-built-from-request
  const v = cache.get(req.query.key as string);
  // ok: sql-built-from-request
  const m = /a(b)/.exec(req.query.s as string);
  res.json({ v, m });
});
