# Upgrade notes

What changes for an existing project when it moves to this engine, beyond what the release notes'
one-line entries say. Newest first.

## Unreleased

### A push leaves a bucket's runtime settings alone unless the schema names them

A push used to rewrite every column of every bucket the schema has, on every push, up-to-date ones
included. A bucket made public in Studio, or given a size limit through the storage API, went back
to what the schema said, and for a bucket that said nothing, back to private with no limit.

A push now creates a missing bucket as before, private unless the schema says otherwise. On a bucket
that exists it rewrites only what the schema names:

| The bucket's entry names | A push rewrites |
|---|---|
| `accessMode`, or `public` | `access_mode` and `public` |
| `allowedMimeTypes` | `allowed_mime_types` |
| `fileSizeLimit` | `file_size_limit` |
| `s3BucketPolicy` | `s3_bucket_policy` |
| none of them | nothing |

A bucket only a file or image field names counts as naming its visibility when the field has an
`accessMode`.

What changes for an existing project:

- **Removing `accessMode` no longer reverts a bucket to private.** Nor does removing a size limit,
  a MIME list or an S3 policy clear it. To change a live bucket from the schema, name the new value;
  to undo a runtime change, name the value you want back.
- **Every row gets a concrete `access_mode`.** A row with none, from an earlier engine or the
  storage service, gets the mode its `public` flag implies, and `public` is set to match a known
  mode (a `custom` bucket is never flagged public). The storage service already read them this
  way, so who can read a bucket does not change. A mode the engine does not know is left alone.
- **`public` may be left out** of a `storageBuckets` entry. It reads as false.
- **The CLI has to stop filling a mode in.** Today it sends `accessMode: "private"` and
  `public: false` for a `Bucket<>` with no `accessMode`, which counts as naming them, so such a
  bucket is still reasserted until a CLI that leaves both out.

### A field write rule judges the row being inserted (MASK-N1)

On `INSERT`, a field's write rule (or its read rule, where it has no write rule) used to be judged
against a row of NULLs, there being no stored row. A rule that reads the row (`Owner<"id">`,
`OwnerFrom`, a membership) was then NULL for every caller, and the value was silently replaced by
the column's default, usually NULL: a user creating their own row could not set their own
owner-only field. Both tiers now judge the values the row stores, defaults included, as an RLS
`WITH CHECK` does: an `owner_id DEFAULT auth.uid()`, a `gen_random_uuid()` key or a serial key is
what a rule reads, and each is evaluated once.

| The caller sends | What happens |
|---|---|
| A value the rule allows | It is stored. |
| A value the rule refuses, other than the column's default | The statement fails with `42501` (`permission denied for column <column> of relation <table>` under tier 2, `column "<table>"."<column>" cannot be written by this role` under tier 1). It used to succeed and drop the value. |
| Nothing, `DEFAULT`, NULL, or the column default's own value | The column takes its default, and is not judged. |

The default's own value counts as no write because PostgREST's `Prefer: missing=default` sends it
for a key a row leaves out. So an admin-only `verified DEFAULT false` is accepted from anyone when
left out or sent as `false`, and `verified: true` from a non-admin is refused. A volatile default
(`gen_random_uuid()`, a sequence) never equals a value sent.

What changes for an existing project:

- **Tier 2 (the `api` views):** the next push rewrites each masked view's write trigger, and stops
  copying a masked column's default onto its view (the base table's is filled in by the trigger).
- **Tier 1 (`supatype_mask`):** the behaviour comes with the Postgres image whose `supatype_mask`
  judges the inserted row. Nothing in the database changes: restarting on that image is enough.
- **Column privileges:** the push no longer takes `INSERT` on a column whose write rule reads the
  row away from `authenticated`, since such a column is now writable on insert. Until the next
  push, an insert naming such a column is refused by the old privilege rather than dropped.
- **`diff` no longer refuses** a required column without a default whose write rule reads the row.
  It still refuses one whose write rule denies everyone, or one narrower than a public create rule.
- **Clients that sent a value they could not write** on create, and relied on it being dropped,
  now get an error, unless the value is the column's default. Send NULL or leave the field out.
- **`service_role` sending NULL** for a masked column that has a default gets the default under
  tier 2 (the trigger cannot tell a NULL it was sent from a column left out), where tier 1 stores
  the NULL. No other caller sees a difference between the tiers.
- **A BEFORE INSERT trigger** on the table (a slug, say) runs after the rules are judged, in both
  tiers, so a rule does not see what such a trigger changes.

### Auto-increment columns: identity on new tables, the table's own style on existing ones (D8)

`AutoIncrement` fields used to be created as `SERIAL` columns. They are now `INTEGER` (or `BIGINT`)
`GENERATED BY DEFAULT AS IDENTITY` columns, with one exception, so that a table never mixes the two:

| Where the column is added | What the push creates |
|---|---|
| A new table | An identity column, `GENERATED BY DEFAULT AS IDENTITY`. |
| An existing table numbered by a serial (a column whose default is `nextval(...)`) and by no identity column | A serial, like the rest of the table. |
| An existing table that already has an identity column, or no auto-increment column at all | An identity column. |

A serial column that already exists stays a serial: the push does not convert it, and `doctor`
does not report it. Only an explicit `Identity` field converts a serial, and the push says so in its
warnings.

Either way, a required auto-increment column added to a table that already has rows numbers those
rows from the column's sequence, in the order Postgres stores them.

### Every model table gets `REPLICA IDENTITY FULL` (F68)

Each push now sets `REPLICA IDENTITY FULL` on every model and junction table it manages, and records
it in the ledger. Tables the schema does not declare are left as they are. If someone sets it back
by hand, `doctor` reports the table as drifted and the next push puts it back.

Why: realtime decides whether to deliver a `DELETE` event by evaluating the subscriber's read rule
against the whole deleted row. Postgres writes the whole old row to the WAL only under
`REPLICA IDENTITY FULL`; with the default identity the WAL carries only the primary key, and
realtime delivers no `DELETE` events at all rather than guess.

What it costs: every `UPDATE` and `DELETE` on a model table now writes the whole old row to the WAL,
not only its key. Write-heavy tables with wide rows produce noticeably more WAL, which means more
disk, more replication traffic and larger base backups. Inserts are unaffected.

**Ship it with the matching realtime image.** The realtime release that judges `DELETE` events from
the whole old row must be deployed with this engine, or after it. On an older realtime image, which
did not check the old row against the subscriber's rules, `FULL` turns a `DELETE` event that leaked
only the row's key into one that leaks the whole row.

The first push after the upgrade sets it on every existing model table. `ALTER TABLE ... REPLICA
IDENTITY` takes a brief `ACCESS EXCLUSIVE` lock on each table but rewrites nothing.

### Rolling back a push that made a table refuses when a column of it was released (F6)

`rollback` of the push that created a table used to drop the table even when one of its columns had
been taken back with `adopt --release` since, losing that column's data. It now refuses, names the
released object, and suggests `adopt --reclaim` to hand it back first. Released ledger rows whose
table no longer exists, and that the schema no longer declares, are removed by the next push.

### `migrate --record` files record what a push records (F7)

`supatype migrate` still prints only the migration, planned without taking any lock an application
waits on. Applied by hand, that file changes the schema and records nothing, and its header says
so: the next push sees objects it did not make.

`supatype migrate --record` prints a file that also creates the engine's own `_supatype` tables and
writes the history row and the ledger rows the push would write, inside the file's own transaction.
Applying that file by hand is the same as pushing: the next push is up to date, and `rollback` undoes
it. To work out those rows, `--record` rehearses the push in a transaction that it always rolls back,
so it needs a role that may run the migration, and it takes the table locks a push takes. It still
changes nothing.
