# vuln_shop — planted-vulnerability fixture

A deliberately tiny Flask app written for Ravel's tests and demos. Its bugs are
planted and documented here, so they are the ground truth:

| Location | Bug | Reachable from a route? |
|---|---|---|
| `shop/db.py` `find_product` | SQL built with `%` from user input (CWE-89) | yes, `GET /search` |
| `shop/app.py` `run_ping` | `shell=True` with user input (CWE-78) | yes, `POST /ping` |
| `shop/app.py` `load_cart` | `pickle.loads` on the request body (CWE-502) | yes, `POST /cart` |
| `shop/db.py` `find_product_safe` | parameterised query: **not** a bug | yes, `GET /search-safe` |
| `scripts/backup.py` `backup` | `shell=True`, but an offline admin script | no |

Never deploy or run it.
