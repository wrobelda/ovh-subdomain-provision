# ovh-subdomain-provision

`provision-https.py` automates provisioning HTTPS for a new subdomain of a
domain whose DNS is hosted at OVH — for example, a newly self-hosted tool
that needs its own certificate. For each subdomain it:

- orders a dedicated DNS zone for the subdomain. This is for
  security, because OVH API keys can only be limited to a given zone, so giving
  each subdomain its own zone means that if someone steals the credentials
  that acme.sh or Caddy holds on its host, they can only affect that one
  subdomain and not the parent domain or any other subdomain on your account;
- delegates the new zone from the parent zone by adding NS records there;
- issues an OVH consumer key limited to that zone only;
- prints the commands to paste on the target host, both as an acme.sh block
  and as a Caddy snippet — use whichever the host runs.

Every step is idempotent, so rerunning the same command after a failure
resumes where it stopped.

## Usage

```sh
# full pipeline: zone + delegation + limited key + host command blocks
./provision-https.py new subdomain.example.com

# check zone state and whether the delegation is visible in public DNS
./provision-https.py status subdomain.example.com
```

## Step by step

For each new subdomain the `new` command walks these steps, skipping any that
are already done, so rerunning the same command after a failure resumes where
it stopped:

1. **Application key + secret** (first run only) — the script opens OVH's
   `createApp` page in your browser, which you will need to log in to using
   your OVH credentials; you then name the application (any name and
   description will do). Once confirmed, OVH displays the key + secret pair,
   which you paste back into the script input — the script then caches it in
   `~/.config/ovh-subdomain-provision/`. This is the one manual copy-paste in the whole
   flow, and since the pair does not expire, you will not need to repeat the
   step.
   NOTE: this key + secret has no power over your account: it only identifies
   this very script, and the one thing it enables is *requesting* consumer
   keys (see below), each of which you will need to independently validate in
   the browser using your OVH credentials.
2. **Admin consumer key** — once the application key is provisioned, we need
   an actual admin key that allows the script to order the zone and modify
   the necessary records programmatically. The script requests one by opening
   OVH's validation page in your browser. You log in with your OVH
   credentials and review the requested API paths, which for
   `subdomain.example.com` would look like this on the validation page:

   ```
   GET     /me                                            -> read account country, needed for the zone order
   POST    /order/cart                                    -> create an order cart
   GET     /order/cart/*                                  -> read the zone offer, verify the order costs 0 before checkout
   POST    /order/cart/*                                  -> order the new DNS zone
   GET     /domain/zone/subdomain.example.com             -> see when the new zone becomes active, read its nameservers
   GET     /domain/zone/subdomain.example.com/record      -> fallback for reading the assigned nameservers
   GET     /domain/zone/subdomain.example.com/record/*    -> read those records' details
   GET     /domain/zone/example.com                       -> detect the parent zone
   GET     /domain/zone/example.com/record                -> check which NS records already exist
   GET     /domain/zone/example.com/record/*              -> read those NS records
   POST    /domain/zone/example.com/record                -> add the NS delegation records
   POST    /domain/zone/example.com/refresh               -> publish the parent zone change
   ```

   The key cannot touch any other zone on the account (for a deeper
   subdomain, every possible parent suffix is listed, since the actual parent
   is not known until the key can query the API). Pick a validity of 1 hour:
   the run spends 15–20 minutes waiting for zone activation, and afterwards
   the key simply expires on its own. As soon as you confirm, the script
   notices the approval (it listens on `127.0.0.1` for the post-approval
   redirect and polls the API) and continues; the key already reached the
   script over the API, so there is nothing to paste.
3. **Zone order** — the script orders a DNS zone for the subdomain (product
   `dns`, plan `zone`), aborting if the checkout is not free, then polls
   until the zone is active — OVH says 15–20 minutes is normal — and reads
   its assigned nameservers.
4. **Delegation** — the script adds matching NS records to the parent zone
   and refreshes it (the parent is detected automatically), then waits until
   the delegation resolves in public DNS via DNS-over-HTTPS.
5. **Per-host consumer key** — the script requests a second key and opens the
   validation page again. This time the listed rules are limited to
   `/domain/zone/<subzone>/…`, and you pick Validity: Unlimited, because
   acme.sh or Caddy will use this key for every renewal. After your
   confirmation the script verifies the key against the new zone.
   NOTE: this key ends up only on the host it serves and can only edit
   records inside that one subzone, so a compromised host cannot touch the
   parent zone or other subdomains.
6. **Hand-off** — the script prints both output variants; use whichever the
   host runs. For acme.sh: env exports with the zone-limited credentials, the
   initial `acme.sh --issue --dns dns_ovh` call (acme.sh persists the
   credentials for renewals), and a crontab line that resolves the full
   acme.sh path and appends a renewal entry only if none exists. For a Caddy
   host: a docker-compose service using `ghcr.io/wrobelda/caddy-ovh` (Caddy
   with the `caddy-dns/ovh` module) plus the matching Caddyfile. Once the
   admin key's hour runs out, the only things left are the powerless
   application pair on your machine and the subzone-limited key on the host.

In total, a new subdomain costs two browser validations. The `status` command
works the same way with a read-only key: one validation, where a 5-minute
validity is plenty.

## Notes

- When Let's Encrypt ships `dns-persist-01` and clients support it, steps 2–5
  collapse into publishing one static `_validation-persist.<subdomain>` TXT
  record; only the hand-off step remains.
