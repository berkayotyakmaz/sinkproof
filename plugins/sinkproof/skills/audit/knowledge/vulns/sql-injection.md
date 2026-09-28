# SQL Injection
CWE-89 · OWASP A03:2021 · ASVS V5.3.4

## What it is
Untrusted data becomes part of the SQL text instead of a bound parameter, so an attacker can change the query.

## Where to look
- Sinks: string concatenation or interpolation into `query`, `execute`, `raw`, `$queryRawUnsafe`, `sequelize.query`, `knex.raw`, `DB::raw`, `whereRaw`, `cursor.execute(f"…")`, `.extra()`, `RawSQL`, `find_by_sql`, `createNativeQuery`.
- Also: identifiers (`ORDER BY ${sort}`, table or column names), `LIKE` patterns, `IN (…)` lists built by joining strings.

## How to confirm
Show untrusted data reaching the SQL string without parameter binding. For identifiers, show there is no allow-list.

## False-positive traps
- Placeholders (`?`, `$1`, `:name`, `%s` passed as a separate argument) are safe; `%s` used with Python `%` formatting is not.
- ORM query builders (`where({ id })`, `filter(id=…)`) are safe; their raw APIs are not.
- Tagged templates such as Prisma ``$queryRaw`…${x}` `` bind parameters; `$queryRawUnsafe` does not.
- Values cast to numbers before use (`parseInt` checked for `NaN`) are safe for numeric positions.

## Safe patterns
```js
db.query("SELECT * FROM products WHERE name LIKE ?", [`%${q}%`]);
const SORT = { price: "price", name: "name" };
db.query(`SELECT * FROM products ORDER BY ${SORT[req.query.sort] ?? "name"}`);
```

## Fix guidance
Bind every value as a parameter. Map identifiers through an allow-list. Use least-privilege database accounts as defense in depth.

## Severity guide
- Impact `high`: the database holds user data or the injection allows writes.
- Impact `medium`: read-only access to limited data.
- Impact `low`: a database with no sensitive data.
- Exploitability: `high` when unauthenticated or ordinary users reach it; `medium` when a specific role is needed; `low` for admin-only input.
