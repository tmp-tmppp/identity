# identity

The identity provider of **Chance**: Keycloak 26 with the realm `chance`. Users log in here, and every service
checks the tokens it issues. A user may belong to several organizations (tenants), so a token carries exactly one of
them: the web app signs in with the scope `chance-organization:<alias>`, and the token holds that organization in the
`organization` claim (the alias is the tenant id) with the user's role there, the group `/tenant-admin` or `/trader`
of that organization (`organization.<alias>.groups`), plus the audience `chance`. `platform-admin` stays a realm role
(`realm_access.roles`); `realm_access` no longer carries a tenant role (token contract v2). The tenants service keeps
the organizations, members and groups in sync through Keycloak's Admin REST API; the payments, market-maker and
markets services get their own service tokens (no admin rights), which the other services accept like any token of
the realm.

## What this repository holds

| Path | What |
|---|---|
| [`realm/chance-realm.json`](realm/chance-realm.json) | The realm, imported on the first start; secrets are `${...}` placeholders filled from the environment |
| [`Dockerfile`](Dockerfile) | Optimized Keycloak image (build options fixed at build time) with the realm file |
| [`docker-entrypoint.sh`](docker-entrypoint.sh) | Refuses to start when a setting is missing, so no placeholder can stay in the realm |
| [`src/realm-check.ts`](src/realm-check.ts) | Static checks of the realm file, run by the unit tests |
| [`helm/`](helm/) | Chart with dev and prod values and a `helm test` smoke test |
| [`compose.yaml`](compose.yaml) | Keycloak, its PostgreSQL and a local mail catcher (Mailpit) for local development and the integration tests |

## The realm

| Item | Setting |
|---|---|
| Organizations | On: one organization per tenant, alias = tenant id; a user may be a member of several |
| Organization groups | `tenant-admin` (manages the tenant, does not trade) and `trader` in every organization; the tenants service creates them and moves a member between them. **No role mappings on these groups**: Keycloak copies roles of organization groups into `realm_access` for every organization of the user, which would leak a role across organizations |
| Realm roles | `platform-admin` (creates tenants). `tenant-admin` and `trader` are retired (no service reads them, nobody is given them, `realm-check.ts` rejects them as default or assigned roles); the definitions stay only until the tenants service stops calling `GET /roles/<name>` and sets groups instead |
| Client scope `chance-organization` | The only scope the realm file defines (the built-in scopes come from `CreateDefaultClientScopes`): the Organization Membership mapper (claim `organization`, access and ID token, no id or attributes) and the Organization Group Membership mapper (access and ID token, group role mappings off). It replaces the built-in `organization` scope, which cannot take the group mapper through an import (an import creates a scope by name and the built-in one exists already) |
| Client `web` | Public client of the web app: authorization code flow with PKCE (S256), no password or implicit flow, redirects only to `CHANCE_WEB_URL`; default scope `chance-organization` (not the built-in `organization`), requested as `chance-organization:<alias>` so that exactly one organization is in the token; the audience `chance`; no offline tokens |
| Client `tenants` | Confidential service account of the tenants service: client credentials only; admin roles `manage-organizations`, `manage-users`, `view-users`, `query-users`, `view-realm`; scopes `basic`, `roles` and `kc-admin-api` (since Keycloak 26.8 the Admin REST API rejects tokens without it with 401) |
| Client `payments` | Confidential service account of the payments service: client credentials only; **no** admin role of any kind and no `kc-admin-api` scope, so the Admin REST API refuses its token; scopes `basic` and `roles` only; an audience mapper puts `chance` into its access token, so the other services (trading) accept it |
| Client `market-maker`, client `markets` | Confidential service accounts like `payments` (client credentials only, no admin role, no `kc-admin-api`, scopes `basic` and `roles`, audience mapper for `chance`); their tokens call the trading service's internal API. Secrets `MARKET_MAKER_CLIENT_SECRET` and `MARKETS_CLIENT_SECRET` |
| Client `tenants-markets` | Confidential service account like `payments`, used only by the tenants service for its calls to the internal admission endpoint of markets: audience `chance`, no Admin REST API access. The client `tenants` holds the admin roles and carries no audience mapper, so no service accepts its token (the realm check fails on a client with admin roles and an audience mapper) |
| Token mappers | `web`, `payments`, `market-maker`, `markets` and `tenants-markets` hold exactly one protocol mapper each, the audience mapper for `chance` (access token only, no client audience); `tenants` holds none; the scope `chance-organization` holds exactly the two organization mappers. A hardcoded role or claim mapper could put `platform-admin` or an organization into a token, so `realm-check.ts` rejects every other mapper |
| First platform admin | User `PLATFORM_ADMIN_USERNAME` with the address `PLATFORM_ADMIN_EMAIL` (imported as verified, so no mail is sent), the name `Platform Admin` and a temporary password: its first login asks only for a new password (`realm-check.ts` rejects a missing or literal address, an unverified one, an empty name and any other required action) |
| Sign-up | The realm's own registration flow `chance registration` (the realm's `registrationFlow`): Keycloak's form with the user profile and **no password**. With `verifyEmail` on, the step *Password Validation* gives the new account the required action `UPDATE_PASSWORD`, which comes after `VERIFY_EMAIL`: whoever follows the mail link chooses the password. Since 2026-11-12 (ADR-0062) the option `always_set_password_on_register_form` is refused by `realm-check.ts`: a password chosen on the form before the address is verified stays valid when the owner of the address follows the mail (T3 below) |
| E-mail verification | `verifyEmail` on: after sign-up Keycloak sends a mail with a confirmation link, and the token's `email_verified` becomes `true` only once the user has followed it (markets admits a "profiles" share link only then). The mail server is `smtpServer`, every server-specific value a `${SMTP_...}` placeholder (`realm-check.ts` rejects a literal host, login or password); the sender's display name is `Chance` |
| Password reset | `resetPasswordAllowed` on: *Forgot Password?* under the password field starts Keycloak's built-in flow `reset credentials`, which mails a reset link to the account's address through the same `smtpServer`; the link asks for a new password, which replaces any other. It is also how the owner of an address links Google to an account whose password they do not know (see "Account takeover protections"). `realm-check.ts` requires it while sign-up is on and refuses another reset flow |
| Google login | The identity provider `google` (Keycloak's Google provider) on the login page next to the user name and password form: client `${GOOGLE_CLIENT_ID}` and `${GOOGLE_CLIENT_SECRET}`, scopes `openid email profile`, `trustEmail` on (an address Google has verified counts as verified, so a "profiles" share link admits it), the profile taken from Google at the first login only (`syncMode` `IMPORT`), Google's tokens not kept, and the realm's own first-login flow `chance first broker login` (also the realm's `firstBrokerLoginFlow`), which links a Google login to an existing account only after that account's password (see "Google login"). No other provider and no provider mapper; `realm-check.ts` checks each of these |
| Required actions | Listed in full (a realm file that lists them replaces Keycloak's defaults): `UPDATE_EMAIL` **on** (Keycloak adds it switched off), which keeps the address read-only in the account console and on the profile forms; its mail holds no link and its link lifetime is one second (realm attribute `actionTokenGeneratedByUserLifespan.update-email` = `1`), so no user changes their own address; `VERIFY_EMAIL` (priority 50) before `UPDATE_PASSWORD` (57); `TERMS_AND_CONDITIONS` and `delete_account` off as before |
| User names | The user profile is Keycloak's default one (26.8.2) plus a pattern that refuses "@" in a user name; Google users get `google.<Google's sub>` (provider mapper `oidc-username-idp-mapper`, the only one). Only the realm attributes `CreateDefaultClientScopes` and the e-mail change lifetime are allowed (a per-type link lifetime would override the 300 s), and `internationalizationEnabled` is false (the mail warnings are English only) |
| Lifetimes | Login pages 15 minutes (`accessCodeLifespanLogin` 900; Keycloak's default 30), required action pages 5 minutes (`accessCodeLifespanUserAction` 300), mailed links 5 minutes (`actionTokenGeneratedByUserLifespan` 300); `realm-check.ts` refuses longer ones |
| Verification mail | `localizationTexts.en.emailVerificationBody` and `...BodyHtml`: Keycloak's text plus "If you did not create this account, do not click the link and ignore this mail: without the link nobody can use the account" |
| Security | TLS required for external requests, brute-force protection, passwords of at least 12 characters, access tokens valid for 5 minutes, refresh tokens used once |

Users register themselves, confirm their address from the verification mail and then choose their password, or log
in with Google (the first Google login creates the account, its address already verified when Google has verified it),
and join a tenant with an invite code from the tenants service. The platform admin keeps its local user name and
password. The realm is imported only when it does not exist yet: a changed
realm file reaches an existing server only by importing it again (or by the same change made in the admin console).

### A realm imported before 2026-11-12

A server whose realm was imported earlier keeps Keycloak's built-in registration flow (no password on the sign-up form),
a platform admin without an address, no password reset and no Google login (the realm file gained the last two later
on 2026-11-12, so a realm imported earlier that day needs the last two items only). An admin makes the same changes once
in the admin console, realm `chance` (not needed for a new database; locally `docker compose down -v` does it):

- *Authentication → registration → Duplicate* as `chance registration`; in the copy, the step *Password Validation* →
  *Settings*: alias `chance registration password`, *Always set password on register form* on; then *Bind flow* →
  *Registration flow*.
- *Users → platform-admin*: the address of `PLATFORM_ADMIN_EMAIL`, *Email verified* on, first name `Platform`, last name
  `Admin`.
- *Realm settings → Login → Forgot password* on.
- Once the Google client exists ("Google login" below) and the deploy carries `GOOGLE_CLIENT_ID` and
  `GOOGLE_CLIENT_SECRET`: *Identity providers → Google* with that client id and secret, then in its settings *Scopes*
  `openid email profile`, *Trust Email* on, *Hide on login page* off, *Store tokens* off, *First login flow override*
  `first broker login`, *Sync mode* `Import`. Or with `kcadm.sh` in the container shell of the next section (the
  variables `kcadm` and `cfg` and the `config credentials` line from there), which reads the two values from the
  container's environment, so none is typed:

```bash
$kcadm update realms/chance "${cfg[@]}" -s resetPasswordAllowed=true
$kcadm create identity-provider/instances -r chance "${cfg[@]}" -s alias=google -s providerId=google -s enabled=true \
  -s trustEmail=true -s storeToken=false -s hideOnLogin=false -s 'firstBrokerLoginFlowAlias=first broker login' \
  -s "config.clientId=$GOOGLE_CLIENT_ID" -s "config.clientSecret=$GOOGLE_CLIENT_SECRET" \
  -s 'config.defaultScope=openid email profile' -s config.syncMode=IMPORT
$kcadm get identity-provider/instances/google -r chance "${cfg[@]}"   # the secret shows as **********
```

  Not run here (no Keycloak was started for this change); the admin console labels are those of the 26.x console.

### A realm imported before e-mail verification

A server whose realm was imported before `verifyEmail` and `smtpServer` were in the file keeps the old realm: no
verification mails, and the `SMTP_...` settings are not read. An admin turns it on once (not needed for a new database):

- Admin console, realm `chance`: *Realm settings → Email*: sender `SMTP_FROM`, display name `Chance`, host, port,
  encryption (StartTLS or SSL as in `SMTP_STARTTLS` / `SMTP_SSL`), authentication with the relay's login, then *Test
  connection* (it mails the signed-in admin's address); then *Realm settings → Login → Verify email* on.
- Or with `kcadm.sh`, in a shell inside the Keycloak container, whose environment already holds the `SMTP_...`
  settings and the bootstrap admin (so no value is typed and none reaches a shell history). `kcadm.sh` is not on the
  image's `PATH`, and its default config file under the home folder `/opt/keycloak` cannot be written (read-only root
  file system), so every call names `/opt/keycloak/bin/kcadm.sh` and a config file in the writable `/tmp`:

```bash
kubectl exec -it deploy/identity -- bash      # the Deployment has the release's name; locally: docker compose exec keycloak bash
# inside the container:
kcadm=/opt/keycloak/bin/kcadm.sh
cfg=(--config /tmp/kcadm.config)
$kcadm config credentials "${cfg[@]}" --server http://localhost:8080 --realm master \
  --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD"
$kcadm update realms/chance "${cfg[@]}" -s verifyEmail=true \
  -s "smtpServer.host=$SMTP_HOST" -s "smtpServer.port=\"$SMTP_PORT\"" -s "smtpServer.from=$SMTP_FROM" \
  -s smtpServer.fromDisplayName=Chance -s "smtpServer.ssl=\"$SMTP_SSL\"" -s "smtpServer.starttls=\"$SMTP_STARTTLS\"" \
  -s "smtpServer.auth=\"$SMTP_AUTH\"" -s "smtpServer.user=$SMTP_USER" -s "smtpServer.password=$SMTP_PASSWORD"
$kcadm get realms/chance "${cfg[@]}" --fields verifyEmail,smtpServer   # the password shows as **********
rm /tmp/kcadm.config                          # it holds the admin's tokens
```

  The bootstrap admin must still exist in the `master` realm. If it was replaced by a permanent admin, log in as that
  admin instead: `--user` with its name and no `--password`, so `kcadm.sh` asks for it (that is why the shell is opened
  with `-it`). Locally there is a simpler way: `docker compose down -v` deletes the old database, and the next start
  imports the current realm.

Users who signed up before have `email_verified` false; Keycloak asks each of them to verify the address at the next
login.

## Configuration

The image refuses to start without these settings (`docker-entrypoint.sh`). In Kubernetes the non-secret ones come
from the chart's ConfigMap and the secret ones from the Secret `identity-env` (organization secret `IDENTITY_ENV`).

| Variable | Secret | Meaning |
|---|---|---|
| `KC_DB_URL` | no | JDBC URL of Keycloak's own database, e.g. `jdbc:postgresql://postgres:5432/keycloak` |
| `KC_DB_USERNAME`, `KC_DB_PASSWORD` | **yes** | Its login |
| `KC_HOSTNAME` | no | Public address as the browser sees it; also the issuer of every token |
| `KC_BOOTSTRAP_ADMIN_USERNAME`, `KC_BOOTSTRAP_ADMIN_PASSWORD` | **yes** | Temporary admin of the master realm, used only when the master realm is created |
| `CHANCE_WEB_URL` | no | Where the web app runs (redirect URIs and web origin of the client `web`) |
| `TENANTS_CLIENT_SECRET` | **yes** | Secret of the client `tenants` (the same value as `KEYCLOAK_CLIENT_SECRET` of the tenants service) |
| `PAYMENTS_CLIENT_SECRET` | **yes** | Secret of the client `payments` (the same value as the payments service's `KEYCLOAK_CLIENT_SECRET`) |
| `MARKET_MAKER_CLIENT_SECRET` | **yes** | Secret of the client `market-maker` (the same value as the market-maker service's client secret) |
| `MARKETS_CLIENT_SECRET` | **yes** | Secret of the client `markets` (the same value as the markets service's client secret) |
| `TENANTS_MARKETS_CLIENT_SECRET` | **yes** | Secret of the client `tenants-markets` (the same value as `MARKETS_ADMISSION_CLIENT_SECRET` of the tenants service) |
| `PLATFORM_ADMIN_USERNAME` | no | User name of the first platform admin |
| `PLATFORM_ADMIN_PASSWORD` | **yes** | Its temporary password |
| `PLATFORM_ADMIN_EMAIL` | **yes** (kept out of the tracked files) | Its e-mail address (the address alone, such as `platform-admin@example.com`), imported as verified, so Keycloak never mails it to check it. The real address goes into the organization secret `IDENTITY_ENV` as a line `PLATFORM_ADMIN_EMAIL=<address>`, never into `helm/values-prod.yaml`: the chart keeps the key empty because its schema requires it, and the Secret is listed after the ConfigMap in the Deployment's `envFrom`, so its value wins (`tests/realm.test.ts` checks the order). Without the line Keycloak does not start |
| `SMTP_HOST` | no | Host of the mail relay that sends the verification mails (`mailpit` locally); empty in the chart until the relay is chosen, so Keycloak does not start |
| `SMTP_PORT` | no | Its port: `587` with STARTTLS, `465` with TLS, `1025` for the local Mailpit |
| `SMTP_FROM` | no | Sender address of the mails (the address alone, such as `no-reply@example.com`; the display name is fixed in the realm), on a domain the relay may send for; empty in the chart until then |
| `SMTP_SSL`, `SMTP_STARTTLS` | no | `true` or `false`: TLS from the first byte, or STARTTLS after connecting (Keycloak then refuses a server without it); at most one of them `true` |
| `SMTP_AUTH` | no | `true` or `false`: log in at the relay; `true` needs `SMTP_SSL` or `SMTP_STARTTLS`, so the password never travels in plain text |
| `SMTP_USER`, `SMTP_PASSWORD` | **yes** | The relay's login; set them locally too (any value), although with `SMTP_AUTH=false` Keycloak sends none |
| `GOOGLE_CLIENT_ID` | no | Client ID of the Google OAuth client of the login with Google (type Web application, ending in `.apps.googleusercontent.com`; "Google login" below); empty in the chart until the client exists, so Keycloak does not start. `compose.yaml` holds a placeholder, with which the Google button fails and every other login works |
| `GOOGLE_CLIENT_SECRET` | **yes** | That client's secret; the chart's schema refuses it among the ConfigMap's settings |

Fixed in the image: PostgreSQL, health and metrics on the management port 9000 (`/health/started`, `/health/ready`,
`/health/live`, `/metrics`), plain HTTP behind the gateway (`KC_HTTP_ENABLED`, `KC_PROXY_HEADERS=xforwarded`) and a
local cache for one replica.

## Google login

The login page shows a **Google** button next to the user name and password form (with organizations in the realm the
first page asks for the user name only and shows the button there; the password field and *Forgot Password?* follow on
the second page). The button leads to `/realms/chance/broker/google/login`, Keycloak sends the browser to Google, and
Google sends it back to `/realms/chance/broker/google/endpoint`.

- **A new address.** The first Google login creates the account with Google's address, first and last name. With
  `trustEmail` on, the account's `email_verified` is Google's own `email_verified` claim, so an address Google has
  verified needs no verification mail. The user then joins a tenant with an invite code like any other user.
- **The address of an existing account** (a local sign-up, or the platform admin). The realm's first-login flow
  `chance first broker login` creates no second account and never links silently: `idp-create-user-if-unique` finds
  the account by address or user name, `idp-confirm-link` shows *Account already exists* with *Add to existing
  account*, and the link is made only after the person signs in with **that account's password**
  (`idp-username-password-form`, plus its one-time code if it has one). Who does not know the password uses *Forgot
  Password?* on that page: the reset link goes to the account's address, the new password replaces any other, and the
  link is made after it. The flow has no profile review (the provider's address cannot be changed on the way), no
  mailed link (`idp-email-verification` would leave a stranger's password on the account) and no `idp-auto-link`;
  `realm-check.ts` refuses each of them and any step without its own rule.
- **The platform admin** keeps its local user name and password. Its owner may link Google to it (decision of
  2026-11-12), through the same confirmation and the admin's own password; then that Google account opens the
  platform admin too.

## Account takeover protections

Keycloak 26.8.2's behaviour read from its sources (tag `26.8.2`), the setting that closes each way in, and the check
that proves it: `realm-check.ts` with a failing case in `tests/realm.test.ts`, and step `k` of the local end-to-end
run (`infrastructure/local/e2e/`), which plays attacker and victim in separate browsers against a stand-in for Google
(a second realm `e2e-upstream` in the local Keycloak, created by `run.sh upstream`, never in the realm file).

| | Scenario | Keycloak 26.8.2 | Before 2026-11-12 | Now |
|---|---|---|---|---|
| T1 | A stranger signs up with the victim's address; the victim later logs in with Google | The link by mailed link leaves the account's password (`IdpVerifyAccountLinkActionTokenHandler`, no credential change) | Open: built-in flow linked by mail; the stranger's form password stayed | Closed: link only after the account's password; the owner gets it by the reset mail, which replaces any other (`ResetCredentialsActionTokenHandler.java:86-93`); with the new sign-up order the stranger never had one |
| T2 | The stranger's sign-up session waits at *verify your email* while the victim proves the address elsewhere | `VerifyEmail.java:106-113` restarts a sign-up session whose address got verified; a link followed in another browser removes the original session (`VerifyEmailActionTokenHandler.java:107,161`); the new password's *Sign out from other devices* removes the account's other sessions (`AuthenticatorUtil.java:249-266`) | The waiting session did not continue, but the stranger logged in afresh with the form password | Closed both ways: no password to log in with, and the waiting session gets no code |
| T3 | The victim follows a verification mail for an account they did not create | `VerifyEmailActionTokenHandler.java:125` verifies the address of the account | Open: the address became verified with the stranger's form password (and a verified address opens "profiles" share links, `markets/src/usecases/admit-share-link.ts:24`) | Closed: whoever follows the link sets the password (`RegistrationPassword.java:118-120`, VERIFY_EMAIL before UPDATE_PASSWORD); the mail also says not to click |
| T4 | An attacker's own Google login sets the victim's address (review page, later profile form) | Review profile leaves the address editable (`DeclarativeUserProfileProviderFactory.java:156-186`, IDP_REVIEW); a changed address makes the new account unverified but linked to the attacker's Google (`AbstractIdentityProvider.java:217-219`) | Open: an account with the victim's address, linked to the attacker's Google, survived the victim's later reset | Closed: no review step; with `UPDATE_EMAIL` on the address is read-only on `UPDATE_PROFILE` / `VERIFY_PROFILE` |
| T5 | A signed-in attacker changes the address to the victim's (account console, `kc_action=UPDATE_EMAIL`), then the victim clicks the mail, links Google or resets | Without the `UPDATE_EMAIL` action the address is editable in the account console and on the profile forms (`UpdateEmail.java:84-96`, `DeclarativeUserProfileProviderFactory.java:156-186`; Keycloak adds it off, `DefaultRequiredActions.java:285`). With it, the change mails a link to the new address, and a click from any browser moves the asking account there, verified (`UpdateEmailActionTokenHandler`: `updateEmailNow`, `setEmailVerified(true)`, no session binding) | Open | Closed (review of 2026-11-12): users do not change their own address, an admin does on request. `UPDATE_EMAIL` stays on, so the forms keep the address read-only (switched off, they would change it without any mail); its mail holds no link (`emailUpdateConfirmationBody` without `{0}`) and its link would expire after one second (`actionTokenGeneratedByUserLifespan.update-email` = 1) |
| T6 | Linking from a session (account console *Linked accounts*, `kc_action=idp_link`) | Needs `manage-account` **or** `manage-account-links` (`IdentityBrokerService.java:1188-1191`) | Persistence only, for whoever already holds a session | Unchanged: not a way in; removing `manage-account-links` alone would not stop it, removing `manage-account` would take the console from every user |
| T7 | Google with the platform admin's address, before or after its first login | The first-login flow finds the admin by address. *Forgot Password?* on the password page fills in that account (`ResetCredentialChooseUser.java:63-71`), the reset finishes the first login and links Google (`ResetCredentialsActionTokenHandler.java:86-105`), and the built-in reset flow never asks for the one-time code (`reset-otp`, `DefaultAuthenticationFlows.java:223`, keeps the existing codes by default, `ResetOTP.java:127`, and only has the user set up a new one) | Linked after a mailed link to the admin's address or the admin's password | The admin's password, **or the admin's mailbox** through the reset: whoever reads the admin's mail and holds a Google account with that address links it. Whether the mailbox may count as the admin's proof is an open decision for the owner of the project |
| T8 | Services that trust `email_verified` | `tenants` passes the address and `email_verified` (true only for boolean true) to markets; markets admits share links and shared markets only for a verified matching address (`admit-share-link.ts:24`, `lookup-shared-market.ts:14`); invites are codes; payments, audit, trading, market-data and market-maker match nothing by address | | Unchanged (read only); the rows above keep a verified address with its owner |
| T9 | A stranger's user name catches a victim's first Google login (the victim's Google name, or the victim's address as a user name) | `idp-create-user-if-unique` matches by address, then by user name, and goes to the link (`IdpCreateUserIfUniqueAuthenticator.java:65-140`); the user name mapper `oidc-username-idp-mapper` (target LOCAL) names the new user before that check | The mailed link went to the *other* account's address, whose owner could accept it, so the victim's Google opened the other account | Closed: Google users are named `google.<Google's sub>` (the only provider mapper), and the user profile refuses "@" in a user name, so a stranger can neither take the victim's address as a user name nor guess the name. A user name `google.<sub>` taken by sign-up would only block that Google account's sign-up (it then asks for the stranger's password) |

The column "Before" is read from the sources, not run against the earlier realm. What stays open:

- A person who knows an account's password, or reads its mailbox (the reset mail), owns it; for the platform admin
  that includes linking Google through the reset (T7, an open decision).
- The temporary password of the platform admin is a deployment secret until its first login.
- A sign-up that takes the user name `google.<sub>` of a Google account (the sub is the same for every site that
  account signs in to) blocks that account's sign-up through Google; it gives no access.
- The account console still lets a signed-in user link and remove providers (T6).
- Users cannot change their own address; an admin does it on request (Admin console or REST API). A change asked for
  in the account console still sends the new address a mail, which says that nothing was changed.
- The `tenants` service account holds `manage-users`: a leaked `TENANTS_CLIENT_SECRET` lets its holder reset any user's
  credentials and address, so it means takeover of every account. Fine-grained admin permissions (version 2) would
  narrow it to organization membership (see "Known limitations").

### Setting up the Google client (at deploy)

The client is created by the owner of the Google Cloud project; Keycloak refuses to start until both values are set.
Google's console names as of 2026-11-12 (Google, "Using OAuth 2.0 for Web Server Applications" and "Manage App
Audience", read 2026-11-12):

1. [Google Cloud Console](https://console.cloud.google.com/), the project of Chance (or a new one), *Google Auth
   Platform*.
2. *Branding* (the OAuth consent screen): app name `Chance`, a user support address and a developer contact address;
   when the console asks for them, the domain of the public host under *Authorized domains*.
3. *Audience*: user type **External** ("available to any user with a Google Account"). In *Testing*, Google normally
   admits only the listed test users, but an app that asks only for `openid`, `email` and `profile` is the exception:
   any Google account can sign in and the consent does not expire after seven days. *Publish app* moves it to *In
   production*. For a local test, add your own Google account as a test user anyway.
4. *Data Access* → *Add or remove scopes*: `openid`, `.../auth/userinfo.email` and `.../auth/userinfo.profile` (shown
   as `openid`, `email`, `profile`), nothing else.
5. *Clients* → *Create client* → application type **Web application**, name for example `Chance Keycloak`. *Authorized
   redirect URIs*:
   - `https://<public host>/realms/chance/broker/google/endpoint` for the cluster, where `<public host>` is the host of
     `KC_HOSTNAME`, the address the browser uses for Keycloak (Keycloak builds the redirect URI from it);
   - `http://localhost:8081/realms/chance/broker/google/endpoint` for a local test with a real Google test user.

   *Authorized JavaScript origins* stay empty (Keycloak exchanges the code itself). *Create*, then copy the client ID
   and the client secret; keep the secret when Google shows it, as it may not be shown again.
6. Where the two values go:
   - `GOOGLE_CLIENT_ID` into `helm/values-prod.yaml` (`env`; it is not a secret).
   - `GOOGLE_CLIENT_SECRET` into the organization secret `IDENTITY_ENV` (one more line `GOOGLE_CLIENT_SECRET=<secret>`),
     which the pipeline turns into the Secret `identity-env`. Never into a values file: the chart's schema refuses it.
   - Locally, both into a compose file outside the repository (`../infrastructure/local/README.md`, "Logins"), never into
     `compose.yaml`.
7. A server whose realm exists already gets the provider by hand ("A realm imported before 2026-11-12"); a new database
   imports it with the realm.
8. Check: the login page shows *Google*; a login with a Google account ends in the web app; the account's address is
   verified (*Users → the user → Email verified*).

## Metrics

Keycloak serves Prometheus metrics itself, so the metrics convention of the Node services (`prom-client`, the series
`http_requests_total` and `http_request_duration_seconds`, `METRICS_PORT` 9464) does not apply here; only the way
Prometheus finds them does (REQ-20).

- **Where.** `GET /metrics` on the management port 9000 of the Pod, never on the HTTP port 8080 (`/metrics` there is a
  404, the same as `/health/ready`). Keycloak 26 serves `/metrics` and `/health` on the management interface when
  metrics and health are enabled ([Keycloak, "Configuring the management interface"](https://www.keycloak.org/server/management-interface),
  [Keycloak, "Enabling Keycloak metrics"](https://www.keycloak.org/observability/configuration-metrics), read 2026-11-11).
  The port is the default and fixed in the chart: the container port `management`, the probes and the annotation use it.
- **Options.** `KC_METRICS_ENABLED=true` is a build option, set in the build stage of the `Dockerfile`.
  `KC_HTTP_METRICS_HISTOGRAMS_ENABLED=true` (`--http-metrics-histograms-enabled`, "a histogram with default buckets
  for the duration of HTTP server requests", available only when metrics are enabled) adds the `_bucket` series of
  `http_server_requests_seconds` (Keycloak's own names, Micrometer; no `tenant` label). Both are set in both stages, so
  `start --optimized` never differs from the build.
- **Discovery.** The Pod annotations `prometheus.io/scrape: "true"`, `prometheus.io/port: "9000"` and
  `prometheus.io/path: /metrics` are in `helm/templates/deployment.yaml`, and `podAnnotations` refuses the same keys.
  Prometheus scrapes the Pod address; the container port is named `management` (it carries the probes too), not `metrics`.
- **Not exposed.** The Service lists the HTTP port only (it listed the management port until 2026-11-11; the
  smoke test now checks the realm's discovery document alone, which a ready Pod answers through the Service), and the
  gateway routes `/realms/chance`, `/resources` and a few paths on port 8080, so `/metrics` and `/health` have no route.
- **NetworkPolicy** (off by default). The management port admits the namespace `networkPolicy.metrics.namespace` (default
  `monitoring`, selected by `kubernetes.io/metadata.name`) and nothing else: no Pod of the release namespace uses it, the
  kubelet probes it from the node. Without `networkPolicy.enabled` any Pod of the cluster can reach it.
- **Check locally.** `docker compose up -d --build`, then `curl -s localhost:9001/metrics | head` (the compose file
  publishes 9000 as 9001 on the loopback address) and `curl -s -o /dev/null -w '%{http_code}\n' localhost:8081/metrics`
  for the 404. Not run for this change (no Keycloak was started); the integration test asserts both.

## Run locally

```bash
docker compose up -d --build     # Keycloak at http://localhost:8081 (admin console /admin), health at :9001
docker compose down -v           # stop and delete its data
```

Every mail Keycloak sends (the verification mail after a sign-up, the reset link of *Forgot Password?*, the admin
console's *Test connection*) goes to the local mail catcher [Mailpit](https://mailpit.axllent.org/) (`axllent/mailpit`, pinned by version and digest) and
nothing leaves the machine: open http://localhost:8025, read the mail and follow its link to verify the address. The
mails are gone when the container is removed.

The tenants service's local defaults (`AUTH_ISSUER=http://localhost:8081/realms/chance`, audience `chance`) match
this setup. The *Google* button fails locally (Google refuses the placeholder client of `compose.yaml`) until a real
client is set as described in "Google login".

## Tests

```bash
npm run lint
npm run typecheck
npm test                         # static checks of the realm, the entrypoint and the Dockerfile
npm run test:integration         # builds the image and checks the realm on a real Keycloak (Docker needed, about 2 minutes)
```

The integration tests check the issuer and signing keys, health only on the management port, the resolved
placeholders, the platform admin's forced password change (its only required action) with its verified address and
name, the bound registration flow without the password option, the first-login flow `chance first broker login` with
`UPDATE_EMAIL` on and `VERIFY_EMAIL` before `UPDATE_PASSWORD`, that the `tenants` account can do exactly what the
tenants service does (create an organization, add and remove a member, set a role) but cannot add roles or clients,
that a member's token carries the tenant, the role and the audience `chance`, and that the `payments` account gets
a token by client credentials whose audience contains `chance` and which the Admin REST API refuses, and that the
realm has `verifyEmail` on with the SMTP settings of `compose.yaml` and a verification mail reaches Mailpit. The unit
tests also run `docker-entrypoint.sh` with the mail settings it must refuse (a missing one, a switch other than
`true`/`false`, a login without TLS), with a platform admin address that is not an address and without the Google
client's id or secret. The unit tests also take the Google provider and the password reset apart one setting at a time
(a missing or literal client id or secret, `trustEmail` off, hidden on the login page, another first-login flow, a
silent link, a provider mapper, reset off, another reset flow); with the two rules switched off 35 of them fail. The
integration test reads the provider, its masked secret, its first-login flow and `resetPasswordAllowed` through the Admin
REST API. The unit tests also take each takeover protection apart (describe "account takeover protections": a review
step, a mailed link, a silent link, the password step missing or optional, `UPDATE_EMAIL` off, `UPDATE_PASSWORD` before
`VERIFY_EMAIL`, longer lifetimes, Keycloak's own verification mail text). The sign-up form itself (no password fields,
`UPDATE_PASSWORD` after the mail link), the Google button and where it sends the browser, a password reset through the
reset mail, and the takeover attempts T1 to T9 with the legitimate link are checked by the local end-to-end run in
`infrastructure/local/e2e/` (steps `b`, `i`, `j`, `k`).

## Known limitations

- `manage-users` lets the `tenants` account give any user any realm role, `platform-admin` included (it cannot give
  Keycloak's own admin roles). Fine-grained admin permissions (version 2) can narrow it to the roles `trader` and
  `tenant-admin`; until then the tenants service is the only holder of that secret and it only ever sets those two.
- One replica only (local cache). A second one needs the distributed cache and a load-balancer-friendly setup.
- See "Account takeover protections" for what stays open. A realm imported before 2026-11-12 keeps the password on the
  sign-up form, Keycloak's `first broker login` and `UPDATE_EMAIL` off until it is imported again (or changed the same
  way in the admin console).
- The Google client is created at deploy time, and both of its settings are required: until `GOOGLE_CLIENT_ID` is in
  `values-prod.yaml` and `GOOGLE_CLIENT_SECRET` in `IDENTITY_ENV`, Keycloak does not start (exit 64).
- `KC_HOSTNAME` and `CHANCE_WEB_URL` in `values-prod.yaml` are empty on purpose: their values (`https://<public host>`
  for both; `KC_HOSTNAME` is the issuer without `/realms/chance`) come from the pipeline's public host (plan INF-01).
  Until the pipeline sets them, Keycloak does not start (`identity: missing settings: KC_HOSTNAME CHANCE_WEB_URL`, exit
  64) instead of issuing tokens and redirects for localhost.

## Delivery

The organization's shared workflow runs the checks on every pull request and, on `main`, builds the image once,
pushes it to Docker Hub and deploys it with Helm, followed by the smoke test (Keycloak ready and the realm imported)
and an automatic rollback on failure; see [`.github/workflows/ci-cd.yml`](.github/workflows/ci-cd.yml).

## Implementation notes

- A client with `serviceAccountsEnabled` gets its service-account user at import; only a client that needs admin roles
  (`tenants`) needs an entry in `users`.
- `oidc-audience-mapper` can add an audience in two ways (`included.custom.audience` and `included.client.audience`):
  the realm check requires the first and rejects the second.
- Why a custom scope and not the built-in one (Keycloak 26.8.2, read in its source and docs, not run here): the import
  creates the built-in scopes only when the file defines none (`RealmManager.isCreateDefaultClientScopes`), unless the
  realm attribute `CreateDefaultClientScopes` is `true`; a scope of the file with the name of a built-in one would then
  be created twice. `chance-organization` has another name, so both work. A parameterized request
  `chance-organization:<alias>` finds the scope among the client's default or optional scopes by the mapper type, not by
  the name `organization` (`OrganizationScope`), is rejected when the user is not a member, and replaces the default
  scope of the same name (`TokenManager.getRequestedClientScopes`). Keycloak refuses to mix `scope:<alias>` with a plain
  `scope` or `scope:*` in one request.
- Organization groups through the Admin REST API: `POST /organizations/{id}/groups`, `PUT
  /organizations/{id}/groups/{groupId}/members/{userId}`, `GET /organizations/{id}/members/{memberId}/groups`
  (Keycloak 26.8 REST reference). Which admin role they need is not stated there; the integration test finds out.
- A new required secret (for example `PAYMENTS_CLIENT_SECRET`) stops Keycloak at start (exit 64) until the Secret
  `identity-env` holds it: add it to the organization secret `IDENTITY_ENV` before the deploy. The same holds for
  `SMTP_USER`, `SMTP_PASSWORD` and `PLATFORM_ADMIN_EMAIL` (the admin's real address, a line `PLATFORM_ADMIN_EMAIL=<address>`
  in `IDENTITY_ENV`), and for `SMTP_HOST` and `SMTP_FROM` in the values.
- Why the realm defines its own registration flow (Keycloak 26.8.2, read in its source jars from Maven Central and
  run locally on 2026-11-12): `RegistrationPassword` (the step *Password Validation*, `registration-password-action`)
  treats sign-up as "verify the e-mail first" when the realm has `verifyEmail` on and its option
  `always_set_password_on_register_form` is not `"true"`; it then leaves the attribute `passwordRequired` unset (the
  theme's `register.ftl` renders the password fields only with it), skips the password check, stores no credential and
  gives the new user the required action `UPDATE_PASSWORD`. The built-in flow has no config for that step, and the
  option lives in an authenticator config of the step, so the realm file defines the flow. The import
  (`DefaultExportImportManager.importAuthenticationFlows`) adds the file's configs and flows, then every missing
  built-in flow (`DefaultAuthenticationFlows.migrateFlows`), then binds `registrationFlow` by alias, so the file
  defines only this flow; the browser flow and the others stay Keycloak's.
- The keys of `smtpServer` (Keycloak 26.8.2, read in its source, not run here): `RealmRepresentation.smtpServer` is a
  `Map<String, String>`, so the port and the switches are strings; `DefaultEmailSenderProvider` reads `host`, `port`,
  `from`, `fromDisplayName`, `replyTo`, `envelopeFrom`, `ssl`, `starttls`, `auth` (each switch on only for the exact
  string `true`; STARTTLS also sets `mail.smtp.starttls.required`, so a server without it is refused), and the login
  reads `user` and `password`. `VerifyEmail` asks for verification at login when the realm has `verifyEmail` on and
  the user's address is not verified yet.
- The keys of the Google provider (Keycloak 26.8.2, read on 2026-11-12 in its sources jars from Maven Central, sha1
  checked, not run): `IdentityProviderRepresentation` has `alias`, `displayName`, `providerId`, `enabled` (a boolean),
  `trustEmail`, `storeToken`, `addReadTokenRoleOnCreate`, `authenticateByDefault`, `linkOnly`, `hideOnLogin` (each a
  `Boolean`), `firstBrokerLoginFlowAlias`, `postBrokerLoginFlowAlias` and `config` (a `Map<String, String>`). The config
  keys are `clientId`, `clientSecret`, `defaultScope` (`OAuth2IdentityProviderConfig`) and `syncMode`
  (`IdentityProviderModel`, `LEGACY`, `IMPORT` or `FORCE`); `GoogleIdentityProvider` sets Google's authorization,
  token, user info and key URLs and the issuer `https://accounts.google.com` itself, and
  `GoogleIdentityProviderConfig.validate` fails the import when the file names another issuer.
- The import (`DefaultExportImportManager`) creates the authentication flows first, adding the built-in `first broker
  login` when the file defines none, and the identity providers after them, so `firstBrokerLoginFlowAlias` `first broker
  login` resolves (`RepresentationToModel.toModel`). That flow (`DefaultAuthenticationFlows.firstBrokerLoginFlow`):
  `idp-review-profile` (only for missing profile fields), then `idp-create-user-if-unique` or, for an existing account,
  `idp-confirm-link` (required) followed by `idp-email-verification` or the re-authentication `idp-username-password-form`.
- `trustEmail`: `OIDCIdentityProvider.setEmailVerified` sets a brokered user's `emailVerified` to Google's
  `email_verified` claim when `trustEmail` is on (to `trustEmail` itself when the claim is missing), for a new user and,
  with `syncMode` `FORCE`, at every login; with `IMPORT` an existing account keeps its own state.
- The login page: with organizations in the realm, `OrganizationAuthenticator` shows the identity-first page with the
  providers that belong to no organization (`OrganizationAwareIdentityProviderBean`), and the theme `keycloak.v2`
  renders them as links `social-<alias>`; *Forgot Password?* is part of the password field (`field.ftl`), so it appears
  on the page with the password. The broker paths are `/realms/{realm}/broker/{alias}/login` and
  `/realms/{realm}/broker/{alias}/endpoint` (`IdentityBrokerService`).
