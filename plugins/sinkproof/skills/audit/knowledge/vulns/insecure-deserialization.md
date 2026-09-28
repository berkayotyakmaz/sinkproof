# Insecure Deserialization
CWE-502 · OWASP A08:2021 · ASVS V5.5.3

## What it is
Untrusted data is deserialized using a format/library that can reconstruct arbitrary objects or invoke code during the process, letting an attacker trigger remote code execution, denial of service, or object-injection logic bugs.

## Where to look
- Java: `ObjectInputStream.readObject()` on untrusted bytes, XStream/Kryo/Hessian without a type allow-list.
- Python: `pickle.load`/`loads`, `yaml.load` (without `SafeLoader`), `marshal.loads`, `dill.load` on untrusted input.
- PHP: `unserialize()` on user-controlled data (object injection via `__wakeup`/`__destruct`).
- Ruby: `Marshal.load`, `YAML.load` (vs `YAML.safe_load`), `Oj.load` in object mode.
- Node: `node-serialize`, `eval`-based deserializers, `js-yaml` `load` (vs `safeLoad`/current default `load` which is safe since v4).
- Go: `encoding/gob` decoding attacker-controlled data into interface types; `reflect`-based deserializers.
- Also: session storage using native serialization, message queue payloads, cache values, and file-upload handlers that deserialize on read.
- Polymorphic JSON sinks that reconstruct arbitrary types from a type hint: Jackson `enableDefaultTyping()` / `@JsonTypeInfo(use = Id.CLASS)`, Json.NET `TypeNameHandling` set to anything other than `None`, fastjson `autoType` enabled, .NET `BinaryFormatter`.

## How to confirm
Show untrusted bytes (request body, uploaded file, queue message, cookie/session value) reaching a native/object deserializer or an unsafe YAML/pickle loader, with no schema restriction or safe-mode loader in between.

## False-positive traps
- Data-only formats (JSON via `JSON.parse`/`json.loads`, or YAML loaded with a safe loader) that cannot instantiate arbitrary classes are not vulnerable — the risk is specific to loaders that support object/type reconstruction. The exception is polymorphic JSON deserialization (see sinks above), where a type hint in the JSON itself drives class instantiation — that is vulnerable like any other object deserializer.
- Current `js-yaml` `load()` (v4+) and PyYAML's `yaml.safe_load` are safe by default; only `yaml.load()` without `Loader=SafeLoader` (or the deprecated default in old PyYAML) is at risk.
- Deserializing data that is signed/HMAC-verified before deserialization, with the key never exposed to the client, is not attacker-controlled and is not this issue.
- A fixed allow-list of deserializable classes (Java `ObjectInputFilter`, XStream `allowTypes`) makes an otherwise-native deserializer safe.

## Safe patterns
```python
import yaml
config = yaml.safe_load(untrusted_yaml)  # cannot construct arbitrary Python objects
```

## Fix guidance
Prefer data-only formats (JSON) for untrusted input; if native/object serialization is required, use a safe-mode loader or a strict type allow-list, and verify integrity (signature/HMAC) with a server-only key before deserializing.

## Severity guide
- Impact `high`: deserialization gadget chain leads to remote code execution or full object-injection compromise.
- Impact `medium`: deserialization enables denial of service or limited data tampering without code execution.
- Impact `low`: deserializer reachable only with pre-validated or signed input, or in a sandboxed process.
- Exploitability: `high` when unauthenticated or ordinary users control the serialized payload; `medium` when a specific role is needed; `low` for admin-only input.
