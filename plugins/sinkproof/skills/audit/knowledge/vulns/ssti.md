# Server-Side Template Injection (SSTI)
CWE-1336 · OWASP A03:2021 · ASVS V5.2.5

## What it is
Untrusted data is compiled as template syntax rather than rendered as a data value, letting an attacker execute expressions — and in many engines arbitrary code — on the server.

OWASP Top 10 2021 does not map CWE-1336 to a category; A03 Injection is the closest fit.

## Where to look
- Sinks: `render_template_string`, `Template(userInput).render()` (Jinja2), `pug.render(userInput)`, `ejs.render(userInput)`, `Twig::createTemplate(userInput)`, `ERB.new(userInput).result`, `freemarker.Template` built from user data, `#set`/`#parse` in Velocity fed with input, Handlebars/Nunjucks `compile(userInput)`.
- Any function that takes a template *string* (not a template *file path* with fixed content) built with or equal to user input.
- Also: "preview" or "export" features that let users supply a custom template/layout.
- Express with EJS/Pug/hbs: `res.render(view, req.query)` or `res.render(view, req.body)` passes the entire user-controlled object as template locals — this can also set engine-level options (e.g. Pug's `filename`/`basedir`) rather than just data, which can be more than a plain context-variable pass-through.

## How to confirm
Show untrusted input reaching a template-compile/render call as the template source itself, not as a variable passed into a pre-written template. Confirm the engine evaluates expressions in that syntax (e.g. `{{ }}`, `${ }`, `<% %>`) rather than just substituting values.

## False-positive traps
- Passing user data as a *context variable* into a fixed, developer-written template (`render_template("page.html", name=user_input)`) is normal, safe use — not SSTI. The exception is spreading a whole user-controlled object into the locals/options (e.g. `res.render(view, req.query)`), which can inject engine options, not just data values — check what keys the object can contain before waving it through as "just context."
- Logic-less template engines (Mustache) and sandboxed modes (Jinja2 `SandboxedEnvironment`, Twig sandbox) reduce or eliminate code execution even if the template string is attacker-influenced.
- Auto-escaping affects XSS, not SSTI — escaping output does not stop the template compiler from evaluating attacker-supplied template syntax.
- Static template files loaded from disk by a fixed path are safe even if the path was chosen from an allow-list.

## Safe patterns
```python
from jinja2 import Environment, select_autoescape
env = Environment(autoescape=select_autoescape())
template = env.get_template("email.html")  # fixed file, not user input
html = template.render(username=user_input)  # user input only as data
```

## Fix guidance
Never build the template source from user input. If user-customizable templates are a real requirement, use a sandboxed/logic-less engine, strip expression syntax, and render in an isolated process with no access to secrets or the filesystem.

## Severity guide
- Impact `high`: the engine allows arbitrary code execution reachable by any user.
- Impact `medium`: expression evaluation is possible but sandboxed to limited data access.
- Impact `low`: engine is logic-less or fully sandboxed against code execution.
- Exploitability: `high` when unauthenticated or ordinary users control the template text; `medium` when a specific role is needed; `low` for admin-only input.
