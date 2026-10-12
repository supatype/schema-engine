# Contributing

## Contributor License Agreement

The engine is licensed under the Business Source License 1.1 (see [LICENSE](LICENSE)). Supatype
Ltd also offers it under commercial terms, and each version becomes Apache 2.0 on its Change Date.
To keep all three possible for code you contribute, every contribution needs a signed Contributor
License Agreement (CLA).

- The CLA is a **licence grant, not an assignment**: you keep the copyright in your contribution
  and grant Supatype Ltd a licence to use, relicense and distribute it.
- You sign it once, through **CLA Assistant**, on your first pull request: the bot comments with a
  link, and the pull request can merge once you have signed.
- The agreement's text: [Supatype Contributor License Agreement](https://supatype.com/legal/cla)
  (placeholder; the link is published with the agreement).

Contributing for an employer may need a corporate agreement as well; ask at
[licensing@supatype.com](mailto:licensing@supatype.com).

## Before you open a pull request

The README's [Building](README.md#building) and [Testing](README.md#testing) sections cover the
toolchain and the suites CI runs. A new dependency must carry a licence `deny.toml` allows: CI runs
`cargo deny check licenses`, and `THIRD-PARTY-NOTICES` must be regenerated with
`cargo about generate about.hbs -o THIRD-PARTY-NOTICES`.
