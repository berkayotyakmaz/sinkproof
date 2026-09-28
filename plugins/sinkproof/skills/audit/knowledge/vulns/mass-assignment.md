# Mass Assignment
CWE-915 · OWASP A08:2021 · ASVS V5.1.2

## What it is
Request data is copied wholesale into a model or database update, so a user can set fields they should never control, such as `role`, `isAdmin`, `balance`, `ownerId` or `emailVerified`.

## Where to look
- Sinks: `Model.update(req.body)`, `Object.assign(user, req.body)`, `{...req.body}` passed to create/update, `Model(**request.json)`, `serializer.save()` with `fields = "__all__"`, Rails `params.permit!`, Laravel `$guarded = []` or `Model::create($request->all())`, Mongoose `findByIdAndUpdate(id, req.body)`.
- Hot spots: profile update, registration, account settings, admin-lite endpoints, PATCH endpoints.

## How to confirm
Show that a request field reaches the write unfiltered, and that the model or table has at least one sensitive field the endpoint should not accept. Name that field in the evidence.

## False-positive traps
- A validation schema that strips unknown keys (Joi/Zod with strict objects, Pydantic models, DRF serializers with explicit `fields`, Rails strong params with `permit(:name, :email)`) makes it safe — check the schema, not only the handler.
- If the model truly has no sensitive fields, report as ARC hardening with low impact at most, not SEC.

## Safe patterns
```js
const { name, bio } = req.body;
await db.query("UPDATE users SET name = ?, bio = ? WHERE id = ?", [name, bio, req.user.id]);
```

## Fix guidance
Allow-list the fields each endpoint may change (explicit destructuring, strict schema, strong params, `$fillable`). Never deny-list.

## Severity guide
- Impact `high`: privilege fields (`role`, `isAdmin`), money fields (`balance`, `credits`) or ownership and verification fields (`userId`, `tenantId`, `emailVerified`) are writable.
- Impact `medium`: other fields whose change breaks business rules.
- Impact `low`: only harmless fields can be set.
- Exploitability: `high` when any logged-in user can call the endpoint; `medium` when a specific role is needed.
