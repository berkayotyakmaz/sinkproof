# NoSQL Injection
CWE-943 · OWASP A03:2021 · ASVS V5.3.4

## What it is
Untrusted data is passed into a NoSQL query as structure (an object, operator or expression) rather than as a plain scalar value, letting an attacker change query logic — e.g. injecting `$where`, `$ne`, `$gt` or a JavaScript expression into MongoDB, or a Cypher/N1QL fragment into a graph or document store.

OWASP Top 10 2021 does not map CWE-943 to a category; A03 Injection is the closest fit.

## Where to look
- Sinks: `Model.find(req.body)`, `collection.find({ field: req.query.x })`, `$where`, `mapReduce`, `db.eval`, raw Mongoose `Model.find(JSON.parse(input))`.
- Python: PyMongo `collection.find(request.json)`, `$where` clauses built from strings.
- PHP: MongoDB driver `find()` fed with `$_GET` arrays directly.
- Ruby: Mongoid `where(params[:query])`.
- Java: MongoTemplate `Query` built from raw JSON, `BasicDBObject.parse(userInput)`.
- Go: `bson.M{}` populated from unvalidated request bodies.
- Also: Elasticsearch/OpenSearch query DSL built by string concatenation, Redis `EVAL` with untrusted script text, Neo4j Cypher built by string interpolation.

## How to confirm
Show untrusted input reaching a query object or filter without type/shape validation, so an attacker-controlled key (e.g. an operator) or nested object can appear where a scalar was expected. For Cypher/N1QL/Elasticsearch DSL, show string concatenation of untrusted data into the query text.

## False-positive traps
- Mongoose schema casting does not reject operator objects passed for a field — only `sanitizeFilter()` (applied per query, or globally via `mongoose.set("sanitizeFilter", true)`) or explicit casting (`String(input)`/`Number(input)`) before the query makes it safe. Don't credit schema typing alone.
- Passing only a single validated, typed field (`Model.find({ id: Number(req.params.id) })`) is safe even without a library sanitizer.
- MongoDB drivers with `mongo-sanitize`/`express-mongo-sanitize` middleware applied before the route are safe.
- Query builders that whitelist allowed filter keys and reject unknown ones are safe.
- `$where`/server-side JS execution disabled in MongoDB configuration reduces but does not eliminate the risk of accepting raw filter objects.
- Express 5's default "simple" query-string parser does not build nested objects/operators from `req.query` (e.g. `?field[$ne]=1` stays a flat string), unlike Express 4's `qs`-based parser — but JSON request bodies can always carry nested operator objects regardless of the query parser, so `req.body` is not protected by this.

## Safe patterns
```js
const { sanitizeFilter } = require("mongoose");
const id = String(req.params.id);
await User.find(sanitizeFilter({ _id: id }));
// or: build the filter explicitly instead of passing req.body/req.query through
await User.find({ email: String(req.query.email) });
```

## Fix guidance
Never pass a raw request object as a query filter. Validate and coerce each field to an expected scalar type, reject unexpected keys (especially ones starting with `$`), use `sanitizeFilter`/the `mongo-sanitize` package, and disable server-side JavaScript execution where the database supports it.

## Severity guide
- Impact `high`: the query controls authentication/authorization checks or exposes other tenants' data.
- Impact `medium`: limited data exposure or filtering bypass on non-sensitive collections.
- Impact `low`: read-only access to already-public data.
- Exploitability: `high` when unauthenticated or ordinary users control the query input; `medium` when a specific role is needed; `low` for admin-only input.
