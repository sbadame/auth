**WARNING: This is just a hobby project of mine, it has not been security reviewed.**
_Seriously, it barely works..._

# ACLs for URLs!

This server authenticates users and applies ACLs to urls.

Only Google Sign is supported.


## How it works

This auth server runs on Cloud Run on a tailnet with my home server.

I have a public domain that points to the Cloud Run instance so all URLs are accesible from the public internet.


```
                 ┌────────────────────────────────────┐
                 │              Tailnet               │
                 │                                    │
External HTTPS───┼─►Auth Server────HTTP───►Home Server│
                 │   │      ▲                         │
                 │   │      │                         │
                 └───┼──────┼─────────────────────────┘
                     │      │
                     ▼      │
                 Auth user with Google
```

### Typical flow.

The Auth server is an HTTP server.

When a request comes in for a URL `/honeypot` the Auth server redirects the request to `/login&target=honeypot`.

Once on the `/login` page, the user is prompted to login. Once the user is authorized by Google, then a cookie `id_token` is set for the domain.

The user is then redirected back to the `target` URL.

The Auth server again sees the URL, but now with the cookie set. The Auth server verifies the JWT in the cookie extracts the username and checks if it matches the ACL.

## Future work

* Support webauthN
* Remove the need for a special /login URL.
* Support having different ACLs for different users.
* Support changing ACLs on the fly
* Support using the backend to store the ACLs so that the frontend can stay stateless.
