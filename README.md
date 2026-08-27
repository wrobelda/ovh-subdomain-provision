# ovh-subdomain-provision

`provision-https.py` automates provisioning HTTPS for a new `subdomain` of a
domain whose DNS is hosted at OVH — for example, a newly self-hosted tool
that needs its own certificate. For each `subdomain` it:

- orders a dedicated DNS zone for the `subdomain`. This is for
  security, because OVH API keys can only be limited to a given zone, so giving
  each `subdomain` its own zone means that if someone steals the credentials
  that acme.sh or Caddy holds on its host, they can only affect that one
  `subdomain` and not the parent domain or any other `subdomain` on your account;
- delegates the new zone from the parent zone by adding NS (nameserver) records there;
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

For each new `subdomain` the `new` command walks these steps, skipping any that
are already done, so rerunning the same command after a failure resumes where
it stopped:

1. **Application key + secret** (first run only):
   * the script opens OVH's `createApp` page in your browser,
   * you log in with your OVH credentials
   * you name the application (any name and description will do),
   * OVH displays the key + secret pair
   * you paste those back into the script input,
   * the script caches the pair in `~/.config/ovh-subdomain-provision/`,
   * and continues to the next stage.

   This is the one manual copy-paste in the whole flow, and since the pair
   does not expire, you will not need to repeat the step.

   **NOTE**: this key + secret has no power over your account: it only identifies
   this very script, and the one thing it enables is *requesting* consumer
   keys (below), each of which you will need to independently validate in
   the browser using your OVH credentials.
2. **Admin consumer key** — the actual key that lets the script order the
   zone and modify the necessary records programmatically:
   * the script opens OVH's validation page in your browser,
   * you log in with your OVH credentials,
   * you review the requested API paths, which for `subdomain.example.com`
     should look like this on the validation page:

      ```
      GET     /me                                            -> read account country, needed for the zone order
      GET     /me/order                                      -> list recent orders, only used if placing the order fails
      GET     /me/order/*                                    -> find the already-placed zone order, track its delivery
      POST    /order/cart                                    -> create an order cart
      GET     /order/cart/*                                  -> read the zone offer, verify the order costs 0 before checkout
      POST    /order/cart/*                                  -> order the new DNS zone
      GET     /domain/zone/subdomain.example.com             -> see when the new zone becomes active, read its nameservers
      GET     /domain/zone/subdomain.example.com/record      -> fallback for reading the assigned nameservers
      GET     /domain/zone/subdomain.example.com/record/*    -> read those records' details
      GET     /domain/zone/example.com                       -> parent zone: need to add DNS nameservers of new subdomain
      GET     /domain/zone/example.com/record                -> check which NS records already exist
      GET     /domain/zone/example.com/record/*              -> read those NS records
      POST    /domain/zone/example.com/record                -> add the NS delegation records
      POST    /domain/zone/example.com/refresh               -> publish the parent zone change
      ```

   * you pick a validity of `1 hour`: the run spends 1–20 minutes waiting for
     zone activation, and afterwards the key expires on its own,
   * script detects your approval automatically, no need to paste keys
   * and continues to the next stage.

3. **Zone order**:
   * the script orders a DNS zone (`/domain/zone/<subzone>`) for the `subdomain.example.com`.
      * aborting if the checkout is not free,
      * if the order is rejected because a previous run already placed it, the
     script finds that order in the recent order history and monitors its
     delivery instead,
   * it polls until the zone is active — OVH says 1–20 minutes is normal
   * once ready, it reads the assigned nameservers,
   * and continues to the next stage.
4. **DNS Delegation**:
   * the script adds the `subdomain`'s NS records to the parent zone,
   * it waits until the DNS delegation resolves in public DNS via
     DNS-over-HTTPS service,
   * continues to the next stage.
5. **Per-host consumer key generation**: final stage
   * the script opens the validation page again —
     this time to issue the actual keys needed by acme.sh tool
      * keys are limited to `/domain/zone/<subzone>/…`, i.e. they can only change the `subdomain.example.com` DNS settings.
   * you pick Validity: Unlimited, because acme.sh or Caddy will use this key
     for every renewal,
   * script detects your approval automatically, no need to paste keys
   * script verifies the issued key works against the new `subzone`.

6. **Hand-off** — the script prints both output variants; use whichever the
   host runs:
   * for acme.sh:
     *  env exports with the required credentials
     *  the initial
     `acme.sh --issue --dns dns_ovh` call (acme.sh persists the credentials
     for renewals)
     *  a crontab renewal entry with the full acme.sh path, and a
     commented `--install-cert` template for copying the cert to a stable
     path with a reload command,
   * for a Caddy host: 
     * a docker-compose service using
     `ghcr.io/wrobelda/caddy-ovh` (Caddy with the `caddy-dns/ovh` module)
     * the matching Caddyfile.

7. After ~1 hour, the admin key's validity runs out.
