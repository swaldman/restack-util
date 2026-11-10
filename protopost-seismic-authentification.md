# protopost / seismic authentication

### Introduction 

Together, `protopost` and `seismic` intend to bridge the gap between a traditional 
CMS-style blog host and static-site generators. 

* `protopost` will be user-facing — users will log in, like they might to an 
   installation of WordPress, Drupal, etc. Users will write and edit posts, 
   then hit "publish".
* `seismic` (from **s**tatic **s**ite **m**anager) will manage a universe of 
   static sites, rebuilding sites on demand (when users explicitly publish or revise a post), 
   or in response to certain events (like discovery of a post from an 
   RSS-subscribed site intended to comment on one of this blog's posts).

The relationship between `protopost` and `seismic` installations should be
many-to-many. One `protopost` installation should be able to manage posts and
comments for blogs managed by multiple `seismic` installations. One `seismic` 
installation should be able to accept posts and comments from multiple installations 
of `protopost`.

Authentication for this system is fairly challeging. Each `protopost` and `seismic` instance 
must be able to authenticate to one another. Client applications need to authenticate on 
behalf of human usres ("posters").

### Some desiderata

1. Client applications should not have to authenticate to both systems. `protopost`
   should manage all interaction with clients, then forward client-driven actions to
   `seismic` installations under the `protopost` installation's authority.
2. Client applications should mostly be authenticated via stateless, long-lived
   client-side tokens. Higher-stakes activities (publishing a new or revised post,
   as opposed to merely editing) should require a "fresher" sign-in, but logins for
   composing and editing should be durable.
3. `seismic` installations should have no authentication relationship with end-user
   clients, but should merely declare ("whitelist") the set of `protopost`
   installations for which they mean to host.
4. `protopost` installations must both authenticate end-user clients and declare a
    set of `seismic` installations to which it will publish.
5. Only mutual relationships function. A mutual relationship exists when `seismic`
   whitelists a `protopost` instance which itself declares a hosting relationship
   to the `seismic` installation. Attempts by a `protopost` installation to post 
   to a non-mutual `seismic` instance will be refused.

### Proposed architecture

1. Both `protopost` and `seismic` installations have identities determined by a 
   private key, and published via a [JSON Web Key Set](https://stytch.com/blog/understanding-jwks/), 
   ~~at an API endpoint (`/jwks.json`) and, for installations hosted at the root-level of a domain,~~ 
   at the [conventional path](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets) 
   `https://{yourDomain}/.well-known/jwks.json`
2. Upon login, client applications will be issued two signed [JWTs](https://jwt.io/)~~, which they 
   will hold in local storage~~ as Cookies set with `SameSite=Strict` to prevent cross-site scripting 
   (XSS) attacks. ~~(Clients must take great care to sanitize inputs in order to prevent XSS attacks!)~~ 
   One token will expire within a configurable relatively quickly. The other will last a configurable 
   number of days. Client API calls to `protopost` will pass the signed JWT, which the `protopost` 
   instance will verify.
   * **Note:** `protopost` authenticates clients old-school, with a username and password stored as 
     a salted bcrypt hash. The hashes are set up so they can be lazily upgraded on login, should 
     growing computational power mean the bcrypt cost factor should increase, or some bug be found 
     in the library.
4. API calls between `protopost` and `seismic` installations will be authenticated by signature, 
   using each installation's published cryptographic identity.
5. Whitelists maintained by `protopost` and `seismic` installations will include a base URL (the 
   URL of the base of API endpoints) and ~~a hash of~~ each partner's public key, Should an 
   installation's "identity" change, administrators of counterpart instances will need to update 
   the public key hash in their configuration. Since each installation knows its counterparts, 
   each installation's administrators should know whom they have to notify.

I think this gets us what we want!
