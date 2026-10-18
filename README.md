# leaksearch — CLI for the leaksear.ch API

A single-file, stdlib-only Python CLI (Python 3.8+, no pip installs) for the
leaksear.ch breach-data API described in described in the leaksear.ch API documentation.

    chmod +x leaksearch.py
    cp leaksearch.example.ini ~/.config/leaksearch/config.ini   # add your api_key
    chmod 600 ~/.config/leaksearch/config.ini

## Quick start

```sh
# check the API key works and show the credit balance
./leaksearch.py --config ~/.config/leaksearch/config.ini --status

# search, poll until the backend finishes, print the redacted summary
./leaksearch.py --config ~/.config/leaksearch/config.ini search foo@example.com

# search, spend credits, stream every record to a JSONL file
./leaksearch.py --config cfg.ini search 'john*' -f username --unlock -y --output hits.jsonl

# resume later: an existing search by id
./leaksearch.py --config cfg.ini status 018f...  --wait
./leaksearch.py --config cfg.ini download 018f... --output records.jsonl
```

Global options (`--config`, `--output`, `--debug`, `--quiet`, `--api-key`,
`--base-url`, `--append`, `--insecure`, `--status`) work before *or* after the
subcommand.

## `--status` — check access and credits

```
$ ./leaksearch.py --config cfg.ini --status
api key    : OK (lsk_...WXYZ)
endpoint   : https://leaksear.ch
config     : /Users/you/.config/leaksearch/config.ini
account    : you@example.com
credits    : 42 available, 10 monthly
unlocks    : up to 42000 results (1000 per credit)
plan       : ACTIVE until 2026-10-01
service    : ok (database up, opensearch healthy)
```

It authenticates against `GET /api/v1/user/credits` — a 200 proves the key
exists and has access — then adds the account, plan and service health as
best-effort extras that never turn a working key into a failure. The summary
above goes to stderr; a JSON report (`ok`, `credits`, `monthlyCredits`,
`subscription`, `profile`, `health`) goes to stdout or `--output`, so
`--status --quiet | jq .credits` is scriptable.

Exit status is **0** when the key works, **3** when it is rejected (the message
then points at `api_key` / `auth_header` / `auth_scheme` in your config), and
**1** if the service could not be reached. Given with a subcommand, `--status`
runs the check *instead of* the command, so nothing is searched or spent.

Note: `--status` is about your *account*; the `status` **subcommand** reports on
a single search id.

## Output

* Progress, polling chatter and the result summary go to **stderr**.
* Data goes to **stdout**, or to `--output FILENAME` (`--append` to add to it).
* Unlocked records are written as **JSONL** by default, one record per line,
  paged through the API 100 at a time. Everything else (summaries, credits,
  history, sources) is pretty-printed JSON.
* **Output files are created `0600`.** Unlocked records routinely contain
  plaintext passwords and must not land in a world-readable file. The ledger and
  watch-state files are written the same way.

So `./leaksearch.py search ... --unlock -y | jq -r .password` works, and the
summary still shows on the terminal.

### Formats — `--format`, `--fields`, `--redact-passwords`

`--format jsonl|json|csv|tsv|table` on `search`, `unlock`, `download`, `resume`
and `watch`. `--fields email,password,leakSourceId` picks and orders the columns
for the tabular formats:

```sh
./leaksearch.py search acme.com -f domain --unlock -y \
    --format csv --fields _query,email,password --output acme.csv
```

`--redact-passwords` replaces every password, hash, salt and pepper with a
stable digest (`redacted:9348ccb935`) — equal passwords stay equal, so reuse
analysis still works on a file you can hand to a client.

## Commands

| Command | What it does |
| --- | --- |
| `search QUERY` | Search, poll `GET /search/:id` until done, print the summary. `--unlock` then spends credits and downloads records. |
| `unlock ID` | Unlock an existing search and download it. |
| `resume ID` | Pick a past search back up: poll it, then download it (`--unlock` to pay for it now). |
| `watch QUERY` | Re-run a search on an interval and report only what is new. |
| `ledger` | List the searches this tool has run locally (ids, spend, output path). |
| `report FILE…` | Summarise downloaded JSONL: sources, email domains, password reuse. |
| `download ID` | Download an already-unlocked search as JSONL. |
| `status ID` | Show a search's status; `--wait` polls until it is ready. |
| `cancel TOKEN` | Cancel an in-flight search. |
| `history` | List past searches. |
| `credits` / `profile` | Account balance / profile (raw JSON; see `--status` for a checked summary). |
| `credits --history` | Credit transactions: purchases, unlocks, monthly refreshes. |
| `sources` | List, filter or inspect indexed leak sources (`--id`, `--stats`). |
| `health` | API health check. |

### Searching

`QUERY` is matched against one field. Without `-f/--field` the field is guessed
(`@` → email, dotted name → domain, digits/dots → ipAddress/phone, else
username) and the guess is printed to stderr. The match type is `EXACT`, or
`WILDCARD` when the query contains `*` or `?` (force it with `-t`).

Up to 5 filters total; add more with `--filter FIELD:QUERY` or
`--filter FIELD:TYPE:QUERY`, combined with `--operator AND|OR` (or per-gap
`--operators AND,OR`). Leak-source filters map 1:1 to the API's
`leakSourceFilters`: `--category`, `--exclude-category`, `--authenticity`,
`--required-field`, `--visibility`, `--breached-since/--breached-until`,
`--indexed-since/--indexed-until`, `--source-min-records/--source-max-records`,
`--source`, `--exclude-source`.

### Polling

Searching costs no credits. Long-running searches return `PENDING`; the tool
polls `GET /search/:id` with a backoff from `--poll-interval` (default 3s) up to
30s, giving up after `--poll-timeout` (default 900s, `0` = wait forever) and
telling you the search id so you can `status`/`download` it later. Ctrl-C during
a search sends the `x-search-cancel-token` to `POST /search/cancel` so the
server stops the query.

### Batch input — `--input`

Point `search` at a file (or `-` for stdin) with one term per line; blank lines
and `#` comments are skipped, duplicates are dropped, and a line may override the
field as `username:jdoe`. Every record is annotated with the term that found it
(`"_query": "foo@example.com"`, disable with `--no-annotate`), so one output file
stays attributable.

```sh
./leaksearch.py search --input scope.txt --unlock -y --budget 20 \
    --concurrency 3 --dedupe --output scope-hits.jsonl
```

`--concurrency N` (default 2) runs N searches at once; `--dedupe` drops records
already written in this run. A per-term summary is printed at the end. Batch
unlocking refuses to start without `--yes` or `--dry-run`, since it spends
credits per term unattended.

### Unlocking (spends credits)

One credit unlocks up to 1000 results. By default the tool asks for exactly
enough credits for the result set and **prompts before spending**; `--credits N`
sets the number explicitly, `--max-credits N` caps a single search, `-y/--yes`
skips the prompt (required in non-interactive use). `--max-records N` stops the
download early.

Two safety rails on top of that:

* **`--dry-run`** runs the search (free) and reports what unlocking *would*
  cost, spending nothing.
* **`--budget N`** (or `max_credits_per_run` in the config) caps what the whole
  invocation may spend. Before the first unlock the live balance is fetched, so
  an unaffordable run is refused up front instead of failing halfway with a 402:

  ```
  balance: only 1 credit(s) available, capping search s-7
  username:jdoe: skipping unlock: no credits available within the budget
  ```

### The ledger — never lose or re-pay for a search

Every search is appended to `~/.local/state/leaksearch/searches.jsonl` (override
with `ledger = …` in the config, disable with `ledger = off` or `--no-ledger`):
search id, filters, result count, unlock status, credits spent and where the
output went.

```sh
./leaksearch.py ledger --limit 10          # table; --format json|jsonl too
./leaksearch.py ledger --unlocked acme     # filter by text, only unlocked ones
./leaksearch.py resume 018f... --output records.jsonl
```

So a polling timeout, a closed laptop or a killed terminal costs you nothing —
the search id is on disk and `resume` picks it up.

### Watch mode

```sh
./leaksearch.py watch acme.com -f domain --interval 3600 \
    --unlock -y --budget 5 --events events.jsonl --output new-hits.jsonl \
    --exec 'notify-send "new breach hits: $LEAKSEARCH_NEW_RECORDS"'
```

Each check re-runs the search and compares the result count and per-source counts
to the stored state. **Checking costs nothing** — only the free metadata view is
polled. Credits are spent only when `--unlock` is given *and* the count has
grown, and only records whose `_id` was not seen on an earlier check are written,
so the output file only ever gains genuinely new hits.

`--interval` (default 3600s, minimum 5), `--count N` to stop after N checks,
`--state FILE` to choose where "what I have seen" lives (default: derived from
the query), `--max-new N` to cap records per check, `--events FILE` to keep
change events out of the record stream, `--exec CMD` to fire a hook (event JSON
on stdin, `LEAKSEARCH_TOTAL` / `LEAKSEARCH_NEW_RECORDS` / `LEAKSEARCH_SEARCH_ID`
in the environment).

### Credit history

```sh
./leaksearch.py credits --history                  # latest 25, as a table
./leaksearch.py credits --history --all --format csv --output spend.csv
./leaksearch.py credits --history --type MONTHLY_CREDITS_USE --type SEARCH_UNLOCK
./leaksearch.py credits --history --all --search <search-id>
```

This is the server's own record of every credit movement: type, signed amount,
balance afterwards, and the search it relates to. Where that search is in the
local ledger, the table shows what was searched (`[email=*@example.com]`)
instead of the bare id, so you can see what each credit was spent on. Without
`--all`, only one page is fetched (`--page`, `--page-size` up to 100).
`--limit N` stops after N matches. `--format table|json|jsonl|csv|tsv`.

Monthly credits and purchased credits are separate pools. `--status` and the
budget guard count both, and the history shows which pool each unlock drew on
(`MONTHLY_CREDITS_USE` vs `SEARCH_UNLOCK`).

### Reporting

```sh
./leaksearch.py report scope-hits.jsonl --format md > findings.md
./leaksearch.py report *.jsonl --top 25 --redact-passwords --resolve-sources
```

Reads JSONL written by this tool (or stdin) and summarises it: record and unique
account counts, plaintext vs hashed split, hits per leak source, email domains,
most common passwords with how many accounts each covers, password reuse, and a
per-search-term breakdown. `--format text|md|json` — `md` is meant for dropping
straight into a deliverable. `--resolve-sources` turns source ids into names via
the API; without it (and for `ledger`) **no API key is needed at all**.

## Configuration

`--config FILE` accepts INI (with or without a `[leaksearch]` header) or JSON
with the same keys — see `leaksearch.example.ini`. Without `--config`, these are
tried in order: `~/.config/leaksearch/config.ini`, `~/.config/leaksearch.ini`,
`~/.leaksearch.ini`, `~/.leaksearch.json`. The key may also come from
`$LEAKSEARCH_API_KEY` or `--api-key` (both override the file).

**Auth header:** `api-1.json` declares no security scheme, so the client sends
`Authorization: Bearer <api_key>`. If the service expects something else, set
`auth_header` / `auth_scheme` in the config (an empty `auth_scheme` sends the
bare key).

## Debugging and exit codes

`--debug` logs every request and response to stderr with the API key redacted.
429/5xx/network failures are retried with backoff, honouring `Retry-After`.

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | general / API error |
| 2 | usage or config error |
| 3 | authentication failed (401/403) |
| 4 | insufficient credits (402) |
| 5 | polling timed out |
| 130 | interrupted |
