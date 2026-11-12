// Static checks of the realm file, run by the unit tests in every pull request: the security settings and the
// token contract that the services rely on (the organization claim with the member's role group, platform-admin,
// audience "chance") must not change by accident, and no secret may be written into the file.

export type Realm = Record<string, unknown>;

/** The realm role the services check (plan section 3). The tenant role is a group of the organization (token contract v2). */
export const REALM_ROLES = ["platform-admin"] as const;

/**
 * The former tenant roles. Token contract v2 reads the tenant role from the member's group in the organization, and a
 * realm role in "realm_access" is ignored, so no user, default role or composite may hold them any more.
 */
export const RETIRED_ROLES = ["tenant-admin", "trader"] as const;

/** Audience that every token for our API carries; the services reject other tokens. */
export const API_AUDIENCE = "chance";

/**
 * The client scope that puts the organization and the member's groups into a token, requested as
 * "chance-organization:<alias>". The built-in "organization" scope cannot take the group mapper through the realm file
 * (an import creates a scope by name and the built-in one exists already), so this scope holds both mappers and the web
 * client uses it instead of the built-in one.
 */
export const ORGANIZATION_SCOPE = "chance-organization";
const MEMBERSHIP_MAPPER = "oidc-organization-membership-mapper";
const GROUP_MAPPER = "oidc-organization-group-membership-mapper";

/** The only admin roles the tenants service account may hold (least privilege). */
export const TENANTS_ADMIN_ROLES = ["manage-organizations", "manage-users", "view-users", "query-users", "view-realm"];

/** Service accounts that only get tokens (client credentials) and call another service; the secret placeholder of each. */
export const TOKEN_CLIENTS: Record<string, string> = {
  payments: "${PAYMENTS_CLIENT_SECRET}",
  "market-maker": "${MARKET_MAKER_CLIENT_SECRET}",
  markets: "${MARKETS_CLIENT_SECRET}",
  "tenants-markets": "${TENANTS_MARKETS_CLIENT_SECRET}",
};

/** The clients the realm may hold: the web app and one service account per service that calls other services. */
export const REALM_CLIENTS = ["web", "tenants", ...Object.keys(TOKEN_CLIENTS)] as const;

/**
 * The mail server that sends the verification mails (verifyEmail): each key of the realm's "smtpServer" and the setting
 * it must read. Every value that differs between the local mail catcher (no TLS, no login) and a real relay (STARTTLS
 * or TLS, a login) comes from the environment; the host, the login and its password must never be written into the
 * tracked realm file. Keycloak reads only the string "true" as on for ssl, starttls and auth.
 */
export const SMTP_SETTINGS: Record<string, string> = {
  host: "SMTP_HOST",
  port: "SMTP_PORT",
  from: "SMTP_FROM",
  ssl: "SMTP_SSL",
  starttls: "SMTP_STARTTLS",
  auth: "SMTP_AUTH",
  user: "SMTP_USER",
  password: "SMTP_PASSWORD",
};

/**
 * Google as a second way to log in, next to the password sign-up (identity brokering). The OAuth client is created in
 * the Google Cloud Console at deploy time: its id and secret come from the environment and are never written into the
 * tracked file. Keys as Keycloak 26.8.2 reads them: clientId, clientSecret and defaultScope (OAuth2IdentityProviderConfig),
 * syncMode (IdentityProviderModel); the provider id "google" sets Google's endpoints and its issuer itself
 * (GoogleIdentityProvider, GoogleIdentityProviderFactory), and an issuer in the file that is not Google's fails the import.
 */
export const GOOGLE_PROVIDER = "google";
export const GOOGLE_SETTINGS: Record<string, string> = {
  clientId: "GOOGLE_CLIENT_ID",
  clientSecret: "GOOGLE_CLIENT_SECRET",
};
export const GOOGLE_SCOPES = ["openid", "email", "profile"] as const;
/** The only keys of the provider's config: the client, its scopes, and the profile imported once (not overwritten at each login). */
const GOOGLE_CONFIG_KEYS = ["clientId", "clientSecret", "defaultScope", "syncMode"];
const GOOGLE_SYNC_MODE = "IMPORT";

/**
 * Keycloak's built-in flow for a user's first login through a provider (DefaultAuthenticationFlows in 26.8.2). The file
 * must not redefine it (an import would replace it), and no provider uses it: its profile review lets the person edit
 * the provider's address before the account is created (IdpReviewProfileAuthenticator), and its mailed link proves the
 * address of the existing account but leaves that account's password in place (IdpVerifyAccountLinkActionTokenHandler).
 */
export const FIRST_BROKER_LOGIN_FLOW = "first broker login";
const AUTO_LINK_STEP = "idp-auto-link";

/**
 * The realm's own first-login flow, bound on every provider and as the realm's default for new ones. It creates an
 * account only for a new address and user name (idp-create-user-if-unique) and otherwise links the existing account only
 * after the person confirms (idp-confirm-link) and signs in with that account's password (idp-username-password-form),
 * plus its one-time code when it has one. Who does not know the password uses "Forgot Password?" there: the reset mail
 * goes to the account's address and the new password replaces whatever password the account had.
 */
export const CHANCE_FIRST_BROKER_LOGIN_FLOW = "chance first broker login";
/** The only steps the first-login flow may hold; every other step needs its own rule here first. */
const FIRST_BROKER_LOGIN_STEPS = ["idp-create-user-if-unique", "idp-confirm-link", "idp-username-password-form", "conditional-user-configured", "auth-otp-form"];
/** Steps that would break the flow's guarantee, and why: named in the problem message. */
const FORBIDDEN_BROKER_STEPS: Record<string, string> = {
  "idp-review-profile": "the review page lets the person change the provider's address, so an account with another person's address is created or linked",
  "idp-email-verification": "the mailed link proves the address but leaves the existing account's password, which a stranger may have chosen",
  [AUTO_LINK_STEP]: "it links a provider's login to an existing account without asking its owner",
  "idp-detect-existing-broker-user": "it links to the existing account without any proof",
  "idp-confirm-override-link": "it replaces another provider link of the account",
};

/**
 * Required actions. A realm file that lists them replaces Keycloak's defaults (DefaultExportImportManager in 26.8.2
 * imports only the listed ones), so the list holds every action the realm uses. UPDATE_EMAIL must be on: then an e-mail
 * change in the account console or on a profile form goes through a confirmation mail to the new address
 * (UpdateEmail), and the address is read-only on those forms (DeclarativeUserProfileProviderFactory); Keycloak adds it
 * switched off. VERIFY_EMAIL must come before UPDATE_PASSWORD, so a new account gets its password only after the mail
 * link and never in the session that registered it.
 */
export const REQUIRED_ACTIONS = ["VERIFY_EMAIL", "UPDATE_PASSWORD", "UPDATE_EMAIL", "UPDATE_PROFILE", "VERIFY_PROFILE"] as const;

/**
 * The longest lifetimes, in seconds: a login page (Keycloak's default 1800), a required action page such as the new
 * password after the mail link, and a link that a user requests by mail (verification, reset, e-mail change).
 */
export const MAX_LIFESPANS: Record<string, number> = {
  accessCodeLifespanLogin: 900,
  accessCodeLifespanUserAction: 300,
  actionTokenGeneratedByUserLifespan: 300,
};

/**
 * Users do not change their own address (an admin does, on request). Keycloak's verified e-mail change mails a link to
 * the new address, and a click from any browser moves the asking account to that address and marks it verified
 * (UpdateEmailActionTokenHandler at 26.8.2: updateEmailNow and setEmailVerified(true), no session binding), so a
 * stranger's account could take over another person's address. The required action UPDATE_EMAIL stays on, because only
 * then is the address read-only in the account console and on the profile forms (UpdateEmail.isEnabled,
 * DeclarativeUserProfileProviderFactory); switched off, those forms would change it without any mail. Its link is made
 * useless instead: the mail text holds no link ({0} is left out) and the link's lifetime is one second.
 */
export const UPDATE_EMAIL_LIFESPAN = "actionTokenGeneratedByUserLifespan.update-email";
export const EMAIL_CHANGE_WARNING = "Chance does not change addresses by mail, so this mail holds no link";
const EMAIL_CHANGE_KEYS = ["emailUpdateConfirmationBody", "emailUpdateConfirmationBodyHtml"];

/**
 * The only realm attributes. Others can change behaviour silently: a per-type link lifetime such as
 * "actionTokenGeneratedByUserLifespan.verify-email" overrides the realm's limit for that link (RealmAdapter at 26.8.2).
 */
export const REALM_ATTRIBUTES: Record<string, string> = { CreateDefaultClientScopes: "true", [UPDATE_EMAIL_LIFESPAN]: "1" };

/**
 * Users created by a Google login get the user name "google.<Google's sub>" (identity provider mapper
 * oidc-username-idp-mapper, target LOCAL), so a stranger cannot make a victim's first Google login land on an existing
 * account by choosing the victim's Google name or address as a user name. A user name never holds "@" (user profile).
 */
export const GOOGLE_USERNAME_TEMPLATE = "google.${CLAIM.sub}";
const USERNAME_MAPPER = "oidc-username-idp-mapper";
const USER_PROFILE_PROVIDER = "org.keycloak.userprofile.UserProfileProvider";

/** The sentence every verification mail carries, plain and HTML, so that a person who did not sign up does not click. */
export const VERIFICATION_MAIL_WARNING = "If you did not create this account, do not click the link and ignore this mail";
const VERIFICATION_MAIL_KEYS = ["emailVerificationBody", "emailVerificationBodyHtml"];

/** Keycloak's built-in flow behind "Forgot password": it mails a reset link to the account's address. */
export const RESET_CREDENTIALS_FLOW = "reset credentials";

/** Settings the realm file reads from the environment; docker-entrypoint.sh refuses to start without them. */
export const REALM_PLACEHOLDERS = [
  "CHANCE_WEB_URL",
  "TENANTS_CLIENT_SECRET",
  "PAYMENTS_CLIENT_SECRET",
  "MARKET_MAKER_CLIENT_SECRET",
  "MARKETS_CLIENT_SECRET",
  "TENANTS_MARKETS_CLIENT_SECRET",
  "PLATFORM_ADMIN_USERNAME",
  "PLATFORM_ADMIN_PASSWORD",
  "PLATFORM_ADMIN_EMAIL",
  ...Object.values(SMTP_SETTINGS),
  ...Object.values(GOOGLE_SETTINGS),
];

/**
 * The sign-up flow. With verifyEmail on, the step "registration-password-action" leaves the password off the form,
 * stores no credential and gives the new user the required action UPDATE_PASSWORD, which comes after the mail link
 * (RegistrationPassword in Keycloak 26.8.2): whoever follows the link chooses the password. Its option
 * ALWAYS_SET_PASSWORD would put the password on the form instead, before the address is verified; then a stranger who
 * signs up with another person's address keeps a working password once that person follows the verification mail, so
 * the option is refused.
 */
export const REGISTRATION_FLOW = "chance registration";
const BUILT_IN_REGISTRATION_FLOW = "registration";
const REGISTRATION_FORM = "registration-page-form";
const PASSWORD_STEP = "registration-password-action";
export const ALWAYS_SET_PASSWORD = "always_set_password_on_register_form";

/** The first platform admin as the realm creates it: only its password is changed at the first login. */
export const PLATFORM_ADMIN = { username: "${PLATFORM_ADMIN_USERNAME}", email: "${PLATFORM_ADMIN_EMAIL}" } as const;

const PLACEHOLDER = /\$\{([A-Z][A-Z0-9_]*)\}/g;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const list = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

const strings = (value: unknown): string[] => list(value).filter((item): item is string => typeof item === "string");

/** Every environment variable named by a ${NAME} placeholder anywhere in the file. */
export function placeholdersIn(realm: Realm): string[] {
  return [...new Set([...JSON.stringify(realm).matchAll(PLACEHOLDER)].map((match) => match[1] ?? ""))].sort();
}

const isPlaceholder = (value: unknown): boolean => typeof value === "string" && /^\$\{[A-Z][A-Z0-9_]*\}$/.test(value);

/** A setting as a problem message shows it: a string as it is, "none" when it is missing, anything else as JSON. */
const shown = (value: unknown): string => (typeof value === "string" ? value : value === undefined ? "none" : JSON.stringify(value));

function client(realm: Realm, clientId: string): Record<string, unknown> | undefined {
  return list(realm["clients"]).filter(isRecord).find((candidate) => candidate["clientId"] === clientId);
}

function checkWebClient(web: Record<string, unknown>, problems: string[]): void {
  if (web["publicClient"] !== true) problems.push("web: must be a public client (a browser cannot keep a secret)");
  if (web["standardFlowEnabled"] !== true) problems.push("web: the authorization code flow must be on");
  if (web["implicitFlowEnabled"] !== false) problems.push("web: the implicit flow must be off");
  if (web["directAccessGrantsEnabled"] !== false) problems.push("web: password grants must be off");
  const attributes = isRecord(web["attributes"]) ? web["attributes"] : {};
  if (attributes["pkce.code.challenge.method"] !== "S256") problems.push("web: PKCE with S256 is required");
  const redirects = strings(web["redirectUris"]);
  if (redirects.length === 0 || redirects.some((uri) => !uri.startsWith("${CHANCE_WEB_URL}/"))) {
    problems.push("web: every redirect URI must start with ${CHANCE_WEB_URL}/ (no wildcards for other hosts)");
  }
  const origins = strings(web["webOrigins"]);
  if (origins.length === 0 || origins.some((origin) => origin !== "${CHANCE_WEB_URL}")) {
    problems.push("web: the only web origin is ${CHANCE_WEB_URL}");
  }
  const scopes = strings(web["defaultClientScopes"]);
  for (const scope of ["roles", ORGANIZATION_SCOPE, "basic"]) {
    if (!scopes.includes(scope)) problems.push(`web: default client scope "${scope}" is missing (the services read its claims)`);
  }
  // The built-in scope carries no group mapper, and a second organization scope next to ours would make Keycloak ask
  // the user which organization to use or reject the request ("organization" mixed with "organization:<alias>").
  if ([...scopes, ...strings(web["optionalClientScopes"])].includes("organization")) {
    problems.push(`web: the built-in client scope "organization" is not allowed (it has no group mapper; the web app uses "${ORGANIZATION_SCOPE}")`);
  }
  // A script on the web app's origin must not obtain offline tokens: they outlive logout and the session limit.
  if ([...scopes, ...strings(web["optionalClientScopes"])].includes("offline_access")) {
    problems.push('web: "offline_access" is not allowed (offline tokens outlive logout and the SSO session limit)');
  }
  if ([...scopes, ...strings(web["optionalClientScopes"])].includes("kc-admin-api")) {
    problems.push('web: "kc-admin-api" is not allowed (a user\'s token must never be an Admin REST API token)');
  }
  checkProtocolMappers("web", web, problems, true);
}

const AUDIENCE_MAPPER = "oidc-audience-mapper";

/** A protocol mapper as a problem message names it: its name and type, never its settings. */
function describeMapper(mapper: unknown): string {
  return isRecord(mapper) ? `"${String(mapper["name"])}" (${String(mapper["protocolMapper"])})` : "that is not an object";
}

/**
 * A token mapper can write any claim into a token, a role or the organization included, so the clients may hold only
 * the mappers the services rely on. A web or service-account client has exactly one: the audience mapper that puts
 * "chance" into the access token (the services reject every other token), and only that audience. The tenants client
 * has none.
 */
function checkProtocolMappers(name: string, client: Record<string, unknown>, problems: string[], audienceRequired: boolean): void {
  const mappers = list(client["protocolMappers"]);
  if (!audienceRequired) {
    if (mappers.length > 0) {
      problems.push(`${name}: no protocol mappers are allowed (has: ${mappers.map(describeMapper).join(", ")}); its token claims come from its scopes`);
    }
    return;
  }
  const audiences = mappers.filter(isRecord).filter((mapper) => mapper["protocolMapper"] === AUDIENCE_MAPPER);
  for (const other of mappers.filter((mapper) => !isRecord(mapper) || mapper["protocolMapper"] !== AUDIENCE_MAPPER)) {
    problems.push(`${name}: the protocol mapper ${describeMapper(other)} is not allowed (the only one is the audience mapper for "${API_AUDIENCE}")`);
  }
  if (audiences.length > 1) problems.push(`${name}: exactly one audience mapper is allowed (has: ${audiences.length})`);
  const audience = audiences[0];
  const config = audience && isRecord(audience["config"]) ? audience["config"] : {};
  if (config["included.custom.audience"] !== API_AUDIENCE || config["access.token.claim"] !== "true") {
    problems.push(`${name}: an audience mapper must put "${API_AUDIENCE}" into the access token`);
  }
  if (config["included.client.audience"] !== undefined && config["included.client.audience"] !== "") {
    problems.push(`${name}: the audience mapper names only the custom audience "${API_AUDIENCE}", no client audience`);
  }
}

/**
 * The realm's own client scopes: exactly one, the organization scope, with the membership mapper (claim "organization",
 * access and ID token) and the group mapper next to it (access and ID token, group role mappings off). Roles on an
 * organization group are copied into "realm_access" for every organization of the user, which would leak a role of one
 * organization into another, so the group mapper never adds them.
 */
function checkOrganizationScope(realm: Realm, problems: string[]): void {
  const attributes = isRecord(realm["attributes"]) ? realm["attributes"] : {};
  if (attributes["CreateDefaultClientScopes"] !== "true") {
    problems.push('the realm attribute CreateDefaultClientScopes must be "true" (an import with its own client scopes creates none of the built-in ones otherwise)');
  }
  const scopes = list(realm["clientScopes"]).filter(isRecord);
  for (const other of scopes.filter((scope) => scope["name"] !== ORGANIZATION_SCOPE)) {
    problems.push(`client scope ${String(other["name"])}: not allowed (the realm file defines only "${ORGANIZATION_SCOPE}"; the built-in ones come from CreateDefaultClientScopes)`);
  }
  const scope = scopes.find((candidate) => candidate["name"] === ORGANIZATION_SCOPE);
  if (!scope) {
    problems.push(`client scope "${ORGANIZATION_SCOPE}" is missing (it puts the organization and the member's group into the token)`);
    return;
  }
  const where = `client scope ${ORGANIZATION_SCOPE}`;
  const mappers = list(scope["protocolMappers"]).filter(isRecord);
  const configOf = (mapper: Record<string, unknown> | undefined): Record<string, unknown> =>
    mapper && isRecord(mapper["config"]) ? mapper["config"] : {};
  const ofType = (type: string) => mappers.filter((mapper) => mapper["protocolMapper"] === type);
  for (const other of mappers.filter((mapper) => ![MEMBERSHIP_MAPPER, GROUP_MAPPER].includes(String(mapper["protocolMapper"])))) {
    problems.push(`${where}: the protocol mapper ${describeMapper(other)} is not allowed (only the organization membership and group membership mappers)`);
  }
  for (const [type, label] of [[MEMBERSHIP_MAPPER, "organization membership"], [GROUP_MAPPER, "organization group membership"]] as const) {
    if (ofType(type).length !== 1) problems.push(`${where}: exactly one ${label} mapper is required (has: ${ofType(type).length})`);
    const config = configOf(ofType(type)[0]);
    if (config["access.token.claim"] !== "true" || config["id.token.claim"] !== "true") {
      problems.push(`${where}: the ${label} mapper must write into the access token and the ID token`);
    }
  }
  const membership = configOf(ofType(MEMBERSHIP_MAPPER)[0]);
  if (membership["claim.name"] !== "organization") problems.push(`${where}: the membership mapper must write the claim "organization"`);
  if (membership["addOrganizationId"] === "true" || membership["addOrganizationAttributes"] === "true") {
    problems.push(`${where}: the membership mapper adds neither the organization id nor its attributes (the services read the alias and the groups)`);
  }
  if (configOf(ofType(GROUP_MAPPER)[0])["addGroupRoleMappings"] === "true") {
    problems.push(`${where}: group role mappings must be off (Keycloak copies them into "realm_access" for every organization of the user)`);
  }
  if (!list(client(realm, "web")?.["defaultClientScopes"]).includes(ORGANIZATION_SCOPE)) {
    problems.push(`web: "${ORGANIZATION_SCOPE}" must be one of its default client scopes (a request for ${ORGANIZATION_SCOPE}:<alias> finds it there)`);
  }
}

function checkTenantsClient(tenants: Record<string, unknown>, realm: Realm, problems: string[]): void {
  if (tenants["publicClient"] !== false) problems.push("tenants: must be a confidential client");
  if (tenants["serviceAccountsEnabled"] !== true) problems.push("tenants: the service account must be on");
  for (const flow of ["standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled"]) {
    if (tenants[flow] !== false) problems.push(`tenants: ${flow} must be off (a service account logs in with client credentials only)`);
  }
  if (!isPlaceholder(tenants["secret"])) problems.push("tenants: the client secret must be a ${...} placeholder");
  // Since Keycloak 26.8 the Admin REST API accepts only tokens with this scope (and its audience): 401 otherwise.
  const tenantsScopes = strings(tenants["defaultClientScopes"]);
  if (!tenantsScopes.includes("kc-admin-api")) problems.push('tenants: default client scope "kc-admin-api" is missing (the Admin REST API answers 401 without it)');
  if (tenantsScopes.some((scope) => !["basic", "roles", "kc-admin-api"].includes(scope))) {
    problems.push("tenants: default client scopes are only basic, roles and kc-admin-api (no profile data in a service token)");
  }
  checkProtocolMappers("tenants", tenants, problems, false);
  const account = list(realm["users"])
    .filter(isRecord)
    .find((user) => user["serviceAccountClientId"] === "tenants");
  const clientRoles = account && isRecord(account["clientRoles"]) ? account["clientRoles"] : {};
  const adminRoles = strings(clientRoles["realm-management"]).sort();
  if (adminRoles.join(",") !== [...TENANTS_ADMIN_ROLES].sort().join(",")) {
    problems.push(`tenants: the service account must hold exactly ${TENANTS_ADMIN_ROLES.join(", ")} (has: ${adminRoles.join(", ") || "none"})`);
  }
  if (account && (strings(account["realmRoles"]).length > 0 || Object.keys(clientRoles).some((key) => key !== "realm-management"))) {
    problems.push("tenants: the service account may hold no other roles");
  }
}

/**
 * A service account that only gets tokens (client credentials) and sends them to another service: payments, and the
 * market-maker and markets clients for the trading service's internal API. It holds no admin role at all and has no
 * admin scope, so the Admin REST API refuses its token.
 */
function checkTokenClient(name: string, secret: string, account: Record<string, unknown>, realm: Realm, problems: string[]): void {
  if (account["publicClient"] !== false) problems.push(`${name}: must be a confidential client`);
  if (account["clientAuthenticatorType"] !== "client-secret") problems.push(`${name}: the client must log in with its secret`);
  if (account["serviceAccountsEnabled"] !== true) problems.push(`${name}: the service account must be on`);
  for (const flow of ["standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled"]) {
    if (account[flow] !== false) problems.push(`${name}: ${flow} must be off (a service account logs in with client credentials only)`);
  }
  if (account["secret"] !== secret) problems.push(`${name}: the client secret must be the placeholder ${secret}`);
  const defaults = strings(account["defaultClientScopes"]).sort();
  if (defaults.join(",") !== "basic,roles") {
    problems.push(`${name}: default client scopes are exactly basic and roles (has: ${defaults.join(", ") || "none"})`);
  }
  if (list(account["optionalClientScopes"]).length > 0) problems.push(`${name}: no optional client scopes (a service token carries no profile data)`);
  if ([...strings(account["defaultClientScopes"]), ...strings(account["optionalClientScopes"])].includes("kc-admin-api")) {
    problems.push(`${name}: "kc-admin-api" is not allowed (its token must never be an Admin REST API token)`);
  }
  checkProtocolMappers(name, account, problems, true);
  // Keycloak creates the service account user when the realm is imported. If the file lists it, it holds no role.
  const user = list(realm["users"])
    .filter(isRecord)
    .find((candidate) => candidate["serviceAccountClientId"] === name);
  if (user) {
    const clientRoles = isRecord(user["clientRoles"]) ? user["clientRoles"] : {};
    if (strings(user["realmRoles"]).length > 0 || Object.values(clientRoles).some((roles) => list(roles).length > 0)) {
      problems.push(`${name}: the service account holds no realm role and no admin role (not even realm-management ones)`);
    }
  }
}

function checkUsers(realm: Realm, problems: string[]): void {
  for (const user of list(realm["users"]).filter(isRecord)) {
    for (const credential of list(user["credentials"]).filter(isRecord)) {
      if (!isPlaceholder(credential["value"])) problems.push(`user ${String(user["username"])}: a credential value must be a placeholder`);
      if (credential["temporary"] !== true) problems.push(`user ${String(user["username"])}: an imported password must be temporary`);
    }
    // An import does not turn "temporary" into the required action (seen with Keycloak 26.8): it must be explicit.
    if (list(user["credentials"]).length > 0 && !strings(user["requiredActions"]).includes("UPDATE_PASSWORD")) {
      problems.push(`user ${String(user["username"])}: an imported password needs the required action UPDATE_PASSWORD`);
    }
    if (strings(user["realmRoles"]).some((role) => (RETIRED_ROLES as readonly string[]).includes(role))) {
      problems.push(`user ${String(user["username"])}: holds a retired tenant realm role (the tenant role is a group of the organization)`);
    }
  }
  const platformAdmins = list(realm["users"])
    .filter(isRecord)
    .filter((user) => strings(user["realmRoles"]).includes("platform-admin"));
  if (platformAdmins.length !== 1) problems.push("exactly one platform admin is created with the realm");
}

/**
 * The first platform admin arrives complete: its address from the environment, already verified, and the first and
 * last name the user profile requires. Without them its first login asks for an address and the names after the new
 * password and then mails a verification link, so the first production login would depend on a working mail relay.
 */
function checkPlatformAdmin(realm: Realm, problems: string[]): void {
  const admin = list(realm["users"])
    .filter(isRecord)
    .find((user) => user["username"] === PLATFORM_ADMIN.username);
  if (!admin) {
    problems.push(`the platform admin ${PLATFORM_ADMIN.username} is missing`);
    return;
  }
  if (admin["email"] !== PLATFORM_ADMIN.email) {
    problems.push(`platform admin: the e-mail address must be the placeholder ${PLATFORM_ADMIN.email} (without one the first login asks for an address and mails a verification link)`);
  }
  if (admin["emailVerified"] !== true) {
    problems.push("platform admin: emailVerified must be true (verifyEmail would otherwise mail a link at the first login)");
  }
  for (const name of ["firstName", "lastName"]) {
    const value = admin[name];
    if (typeof value !== "string" || value.trim() === "" || isPlaceholder(value)) {
      problems.push(`platform admin: ${name} must be a fixed name (the user profile requires it, so the first login would ask for it)`);
    }
  }
  const actions = strings(admin["requiredActions"]);
  if (actions.length !== 1 || actions[0] !== "UPDATE_PASSWORD") {
    problems.push(`platform admin: the only required action is UPDATE_PASSWORD (has: ${actions.join(", ") || "none"})`);
  }
}

/**
 * Sign-up sets the password only after the mail link. Keycloak uses the flow named by "registrationFlow" (the built-in
 * "registration" when the key is missing); the realm binds its own, so that the file states every step. That flow holds
 * exactly one step, the required sign-up form, and the form holds the password step once, required (without it a new
 * account would get no UPDATE_PASSWORD and no password at all), without ALWAYS_SET_PASSWORD "true".
 */
function checkRegistrationSetsPasswordAfterVerification(realm: Realm, problems: string[]): void {
  if (realm["registrationAllowed"] !== true) return;
  const alias = typeof realm["registrationFlow"] === "string" ? realm["registrationFlow"] : BUILT_IN_REGISTRATION_FLOW;
  const flows = list(realm["authenticationFlows"]).filter(isRecord);
  const flow = (name: unknown) => flows.find((candidate) => candidate["alias"] === name);
  const top = flow(alias);
  if (!top) {
    problems.push(`registration flow "${alias}": not defined in the file, so the file does not state its steps; use "${REGISTRATION_FLOW}"`);
    return;
  }
  const steps = list(top["authenticationExecutions"]).filter(isRecord);
  const formStep = steps[0];
  if (steps.length !== 1 || !formStep || formStep["authenticator"] !== REGISTRATION_FORM || formStep["authenticatorFlow"] !== true || formStep["requirement"] !== "REQUIRED") {
    problems.push(`registration flow "${alias}": must hold exactly one step, the required sign-up form (${REGISTRATION_FORM}); another step could create a user without the form's password`);
    return;
  }
  const form = flow(formStep["flowAlias"]);
  if (!form || form["providerId"] !== "form-flow") {
    problems.push(`registration flow "${alias}": the sign-up form "${String(formStep["flowAlias"])}" must be a form flow (form-flow) defined in the file`);
    return;
  }
  const passwordSteps = list(form["authenticationExecutions"]).filter(isRecord).filter((step) => step["authenticator"] === PASSWORD_STEP);
  const passwordStep = passwordSteps[0];
  if (passwordSteps.length !== 1 || !passwordStep || passwordStep["requirement"] !== "REQUIRED") {
    problems.push(`registration flow "${alias}": the sign-up form must hold the password step ${PASSWORD_STEP} once, REQUIRED (with verifyEmail on it gives the new user UPDATE_PASSWORD, so the password is chosen after the mail link)`);
    return;
  }
  const config = list(realm["authenticatorConfig"])
    .filter(isRecord)
    .find((candidate) => candidate["alias"] === passwordStep["authenticatorConfig"]);
  const options = config && isRecord(config["config"]) ? config["config"] : {};
  if (String(options[ALWAYS_SET_PASSWORD]).toLowerCase() === "true") {
    problems.push(`registration flow "${alias}": the password step must not set ${ALWAYS_SET_PASSWORD} (a password chosen on the form before the address is verified stays valid once the address's owner follows the verification mail)`);
  }
}

/** A flow's steps with every subflow opened: each step with the requirements of the subflows on its path. */
type Step = { authenticator: string; requirement: unknown; path: unknown[]; flow: string; priority: number };
function stepsOf(realm: Realm, alias: string, problems: string[], where: string, path: unknown[] = [], seen: string[] = []): Step[] {
  const flow = list(realm["authenticationFlows"]).filter(isRecord).find((candidate) => candidate["alias"] === alias);
  if (!flow || seen.includes(alias)) {
    problems.push(`${where}: the subflow "${alias}" must be defined in the file once (no loop)`);
    return [];
  }
  const out: Step[] = [];
  for (const step of list(flow["authenticationExecutions"]).filter(isRecord)) {
    if (step["authenticatorFlow"] === true) {
      out.push(...stepsOf(realm, String(step["flowAlias"]), problems, where, [...path, step["requirement"]], [...seen, alias]));
    } else {
      out.push({ authenticator: String(step["authenticator"]), requirement: step["requirement"], path, flow: alias, priority: Number(step["priority"]) });
    }
  }
  return out;
}

/**
 * The first login through a provider (Google). An existing account with the same address or user name is linked only
 * after its own password: a mailed link would prove only the address, and the stranger who registered that address
 * would keep their password; a review page would let the person change the provider's address. The flow is the realm's
 * default for new providers too.
 */
function checkFirstBrokerLoginFlow(realm: Realm, problems: string[]): void {
  const where = `first-login flow "${CHANCE_FIRST_BROKER_LOGIN_FLOW}"`;
  if (realm["firstBrokerLoginFlow"] !== CHANCE_FIRST_BROKER_LOGIN_FLOW) {
    problems.push(`firstBrokerLoginFlow must be "${CHANCE_FIRST_BROKER_LOGIN_FLOW}" (a provider added later gets the realm's default first-login flow; has: ${shown(realm["firstBrokerLoginFlow"])})`);
  }
  const top = list(realm["authenticationFlows"]).filter(isRecord).find((flow) => flow["alias"] === CHANCE_FIRST_BROKER_LOGIN_FLOW);
  if (!top || top["topLevel"] !== true || top["providerId"] !== "basic-flow") {
    problems.push(`${where}: must be defined in the file as a top-level basic flow`);
    return;
  }
  const steps = stepsOf(realm, CHANCE_FIRST_BROKER_LOGIN_FLOW, problems, where);
  for (const step of steps) {
    const reason = FORBIDDEN_BROKER_STEPS[step.authenticator];
    if (reason) problems.push(`${where}: the step ${step.authenticator} is not allowed (${reason})`);
    else if (!FIRST_BROKER_LOGIN_STEPS.includes(step.authenticator)) {
      problems.push(`${where}: the step ${step.authenticator} is not allowed (only ${FIRST_BROKER_LOGIN_STEPS.join(", ")})`);
    }
  }
  const named = (name: string) => steps.filter((step) => step.authenticator === name && step.requirement !== "DISABLED");
  const active = (step: Step) => !step.path.some((requirement) => requirement === "DISABLED" || requirement === "CONDITIONAL");
  const create = named("idp-create-user-if-unique");
  if (create.length !== 1 || !create[0] || create[0].requirement !== "ALTERNATIVE" || !active(create[0])) {
    problems.push(`${where}: idp-create-user-if-unique must be there once, ALTERNATIVE (a new address gets a new account, an existing one goes to the link)`);
  }
  const confirm = named("idp-confirm-link");
  const password = named("idp-username-password-form");
  const [confirmStep] = confirm;
  const [passwordStep] = password;
  if (confirm.length !== 1 || password.length !== 1 || !confirmStep || !passwordStep || confirmStep.requirement !== "REQUIRED" || passwordStep.requirement !== "REQUIRED"
    || confirmStep.flow !== passwordStep.flow || passwordStep.priority <= confirmStep.priority || !active(confirmStep) || !active(passwordStep)) {
    problems.push(`${where}: an existing account is linked only after idp-confirm-link and then idp-username-password-form, both REQUIRED, once, in the same subflow (the person confirms and signs in with that account's password)`);
  }
  // The account's second factor after its password: a CONDITIONAL subflow in the same subflow, with the condition
  // conditional-user-configured and auth-otp-form, both REQUIRED.
  const linkFlow = list(realm["authenticationFlows"]).filter(isRecord).find((flow) => flow["alias"] === passwordStep?.flow);
  const secondFactor = list(linkFlow?.["authenticationExecutions"]).filter(isRecord)
    .filter((step) => step["authenticatorFlow"] === true && step["requirement"] === "CONDITIONAL" && Number(step["priority"]) > (passwordStep?.priority ?? Infinity));
  const otpSteps = secondFactor.flatMap((step) => {
    const sub = list(realm["authenticationFlows"]).filter(isRecord).find((flow) => flow["alias"] === step["flowAlias"]);
    return [list(sub?.["authenticationExecutions"]).filter(isRecord)];
  });
  const complete = otpSteps.some((steps) => ["conditional-user-configured", "auth-otp-form"].every((name) => steps.some((step) => step["authenticator"] === name && step["requirement"] === "REQUIRED")));
  if (!complete) {
    problems.push(`${where}: after the password, a CONDITIONAL subflow with conditional-user-configured and auth-otp-form, both REQUIRED, asks for the account's one-time code (a linked provider would otherwise skip the account's second factor)`);
  }
}

/** No user changes their own address: the e-mail change mail holds no link, and its link would expire at once. */
function checkNoEmailChangeByMail(realm: Realm, problems: string[]): void {
  const attributes = isRecord(realm["attributes"]) ? realm["attributes"] : {};
  if (attributes[UPDATE_EMAIL_LIFESPAN] !== "1") {
    problems.push(`attributes.${UPDATE_EMAIL_LIFESPAN} must be "1" (one second: the link of an e-mail change never works; a click on it would move the asking account to the clicker's address, verified; has: ${shown(attributes[UPDATE_EMAIL_LIFESPAN])})`);
  }
  const texts = isRecord(realm["localizationTexts"]) && isRecord(realm["localizationTexts"]["en"]) ? realm["localizationTexts"]["en"] : {};
  for (const key of EMAIL_CHANGE_KEYS) {
    const text = texts[key];
    if (typeof text !== "string" || !text.includes(EMAIL_CHANGE_WARNING) || text.includes("{0}") || text.includes("'")) {
      problems.push(`localizationTexts.en.${key} must say "${EMAIL_CHANGE_WARNING}" and leave out the link {0} (no apostrophe)`);
    }
  }
}

/** Only the realm attributes the file needs, with their values. */
function checkRealmAttributes(realm: Realm, problems: string[]): void {
  const attributes = isRecord(realm["attributes"]) ? realm["attributes"] : {};
  for (const [key, value] of Object.entries(attributes)) {
    if (!(key in REALM_ATTRIBUTES)) {
      problems.push(`realm attribute ${key}: not allowed (only ${Object.keys(REALM_ATTRIBUTES).join(", ")}; a per-type link lifetime would override the realm's limit)`);
    } else if (value !== REALM_ATTRIBUTES[key]) {
      problems.push(`realm attribute ${key} must be "${REALM_ATTRIBUTES[key]}" (has: ${shown(value)})`);
    }
  }
}

/** One language: the warnings in the mails exist in English only, so no other locale may be offered. */
function checkLocales(realm: Realm, problems: string[]): void {
  if (realm["internationalizationEnabled"] !== false) {
    problems.push(`internationalizationEnabled must be false (the mail warnings exist in English only; has: ${shown(realm["internationalizationEnabled"])})`);
  }
  const locales = strings(realm["supportedLocales"]);
  if (locales.some((locale) => locale !== "en") || (realm["defaultLocale"] !== undefined && realm["defaultLocale"] !== "en")) {
    problems.push(`supportedLocales and defaultLocale may only be "en" (has: ${locales.join(", ") || "none"}, ${shown(realm["defaultLocale"])})`);
  }
}

/**
 * The user profile: Keycloak's default one (26.8.2) plus a pattern on the user name that refuses "@", so nobody's user
 * name is another person's address. The address stays editable for users, which sign-up needs (UserProfileContext
 * REGISTRATION is a user context); outside sign-up UPDATE_EMAIL keeps it read-only.
 */
function checkUserProfile(realm: Realm, problems: string[]): void {
  const components = isRecord(realm["components"]) ? list(realm["components"][USER_PROFILE_PROVIDER]).filter(isRecord) : [];
  const where = "user profile";
  const raw = components.length === 1 && isRecord(components[0]?.["config"]) ? list(components[0]?.["config"]["kc.user.profile.config"])[0] : undefined;
  const parse = (text: unknown): Record<string, unknown> => {
    try {
      const parsed: unknown = typeof text === "string" ? JSON.parse(text) : {};
      return isRecord(parsed) ? parsed : {};
    } catch {
      return {};
    }
  };
  const config = parse(raw);
  const attributes = list(config["attributes"]).filter(isRecord);
  const attribute = (name: string) => attributes.find((candidate) => candidate["name"] === name);
  if (components.length !== 1 || components[0]?.["providerId"] !== "declarative-user-profile" || attributes.length === 0) {
    problems.push(`${where}: exactly one ${USER_PROFILE_PROVIDER} component (declarative-user-profile) with a readable kc.user.profile.config is required`);
    return;
  }
  const username = attribute("username");
  const validations = isRecord(username?.["validations"]) ? username["validations"] : {};
  const pattern = isRecord(validations["pattern"]) ? validations["pattern"]["pattern"] : undefined;
  const refusesAt = ((): boolean => {
    try {
      const re = typeof pattern === "string" ? new RegExp(pattern) : undefined;
      return !!re && !re.test("victim@example.com") && re.test("google.112233445566778899") && re.test("platform-admin");
    } catch {
      return false;
    }
  })();
  if (!refusesAt || !isRecord(validations["username-prohibited-characters"]) || !isRecord(validations["length"])) {
    problems.push(`${where}: the user name needs Keycloak's validations and a pattern that refuses "@" (and accepts google.<sub> and platform-admin), so no user name is another person's address`);
  }
  for (const name of ["email", "firstName", "lastName"]) {
    const a = attribute(name);
    const permissions = isRecord(a?.["permissions"]) ? a["permissions"] : {};
    const required = isRecord(a?.["required"]) ? a["required"] : {};
    if (!a || !strings(permissions["edit"]).includes("user") || !strings(required["roles"]).includes("user")) {
      problems.push(`${where}: ${name} must be required and editable by the user (sign-up asks for it)`);
    }
  }
}

/** Every required action the realm relies on is listed and on, and the address is verified before the password is set. */
function checkRequiredActions(realm: Realm, problems: string[]): void {
  const actions = list(realm["requiredActions"]).filter(isRecord);
  if (actions.length === 0) {
    problems.push("requiredActions must be listed (without the list Keycloak adds its defaults with UPDATE_EMAIL off, and an address can be changed without a confirmation mail)");
    return;
  }
  const byAlias = (alias: string) => actions.filter((action) => action["alias"] === alias);
  for (const alias of REQUIRED_ACTIONS) {
    const found = byAlias(alias);
    if (found.length !== 1 || found[0]?.["enabled"] !== true || found[0]?.["providerId"] !== alias) {
      problems.push(`required action ${alias}: must be listed once, enabled, with the provider ${alias}${alias === "UPDATE_EMAIL" ? " (an address changes only after a confirmation mail to the new address, and the profile forms show it read-only)" : ""}`);
    }
  }
  const priority = (alias: string) => Number(byAlias(alias)[0]?.["priority"]);
  if (!(priority("VERIFY_EMAIL") < priority("UPDATE_PASSWORD"))) {
    problems.push(`required action VERIFY_EMAIL must come before UPDATE_PASSWORD (lower priority; has: ${shown(byAlias("VERIFY_EMAIL")[0]?.["priority"])} and ${shown(byAlias("UPDATE_PASSWORD")[0]?.["priority"])}), so a new account gets its password only after the mail link`);
  }
  for (const action of actions) {
    if (action["alias"] === "UPDATE_EMAIL" && isRecord(action["config"]) && String(action["config"]["verifyEmail"]).toLowerCase() === "false") {
      problems.push('required action UPDATE_EMAIL: config.verifyEmail must not be "false"');
    }
  }
}

/** Login pages, required action pages and mailed links expire soon. */
function checkLifespans(realm: Realm, problems: string[]): void {
  for (const [key, max] of Object.entries(MAX_LIFESPANS)) {
    const value = realm[key];
    if (typeof value !== "number" || !Number.isInteger(value) || value <= 0 || value > max) {
      problems.push(`${key} must be set, at most ${max} seconds (has: ${shown(value)})`);
    }
  }
}

/** The verification mail tells a person who did not sign up not to follow the link, in the plain and the HTML part. */
function checkVerificationMail(realm: Realm, problems: string[]): void {
  const texts = isRecord(realm["localizationTexts"]) && isRecord(realm["localizationTexts"]["en"]) ? realm["localizationTexts"]["en"] : {};
  for (const key of VERIFICATION_MAIL_KEYS) {
    const text = texts[key];
    if (typeof text !== "string" || !text.includes(VERIFICATION_MAIL_WARNING) || !text.includes("{0}") || text.includes("'")) {
      problems.push(`localizationTexts.en.${key} must hold the link {0} and the sentence "${VERIFICATION_MAIL_WARNING}" (no apostrophe: Keycloak formats it as a message pattern)`);
    }
  }
}

/** The retired roles must not be in the realm's default role, and no realm role may be a composite that contains them. */
function checkRetiredRoles(realm: Realm, problems: string[]): void {
  const defaultRole = isRecord(realm["defaultRole"]) ? realm["defaultRole"] : {};
  const composites = isRecord(defaultRole["composites"]) ? defaultRole["composites"] : {};
  const defaults = [...strings(composites["realm"]), ...strings(realm["defaultRoles"])];
  for (const role of RETIRED_ROLES) {
    if (defaults.includes(role)) problems.push(`realm role "${role}" is a default role (token contract v2: nobody gets it by default)`);
  }
  const roles = isRecord(realm["roles"]) ? list(realm["roles"]["realm"]).filter(isRecord) : [];
  for (const role of roles) {
    const members = isRecord(role["composites"]) ? strings(role["composites"]["realm"]) : [];
    for (const retired of RETIRED_ROLES) {
      if (members.includes(retired)) problems.push(`realm role ${String(role["name"])}: a composite that contains the retired role "${retired}"`);
    }
  }
}

/**
 * A client whose service account holds Admin REST API roles carries no audience mapper: with the audience "chance" every
 * service would accept its token, and each of them would then hold a bearer that the Admin API accepts too. The calls
 * of such a client to another service are made by a second client without those roles (tenants-markets).
 */
function checkAdminClientsCarryNoAudience(realm: Realm, problems: string[]): void {
  for (const user of list(realm["users"]).filter(isRecord)) {
    const clientId = user["serviceAccountClientId"];
    const clientRoles = isRecord(user["clientRoles"]) ? user["clientRoles"] : {};
    if (typeof clientId !== "string" || strings(clientRoles["realm-management"]).length === 0) continue;
    const mappers = list(client(realm, clientId)?.["protocolMappers"]).filter(isRecord);
    if (mappers.some((mapper) => mapper["protocolMapper"] === "oidc-audience-mapper")) {
      problems.push(`${clientId}: a client whose service account holds admin roles must not carry an audience mapper (its token would be accepted by every service)`);
    }
  }
}

/**
 * Self-registered users must prove their e-mail address (a "profiles" share link admits a caller only when the token's
 * email_verified is true), so verifyEmail is on and the realm has a mail server whose settings all come from the
 * environment: a literal host, login or password here would put an address or a secret into a tracked file.
 */
function checkEmailVerification(realm: Realm, problems: string[]): void {
  if (realm["verifyEmail"] !== true) problems.push("verifyEmail must be on (a self-registered user's address is trusted only after the verification mail)");
  const smtp = realm["smtpServer"];
  if (!isRecord(smtp)) {
    problems.push("smtpServer is missing (verifyEmail needs a mail server to send the verification mail)");
    return;
  }
  for (const [key, name] of Object.entries(SMTP_SETTINGS)) {
    if (smtp[key] !== `\${${name}}`) {
      const literal = ["host", "user", "password"].includes(key) && !isPlaceholder(smtp[key]) ? "; a literal would put an address or a secret into a tracked file" : "";
      problems.push(`smtpServer: ${key} must be the placeholder \${${name}}${literal}`);
    }
  }
  // Keycloak reads further keys too: a secret (authTokenClientSecret for a relay that takes OAuth tokens) would land in
  // the tracked file, and debug writes every mail, verification links included, into the server log. A new key needs
  // its own placeholder and rule here first.
  const allowed = [...Object.keys(SMTP_SETTINGS), "fromDisplayName"];
  for (const key of Object.keys(smtp)) {
    if (!allowed.includes(key)) problems.push(`smtpServer: ${key} is not allowed (only ${allowed.join(", ")})`);
  }
}

/**
 * Google login: exactly one provider, Google, shown on the login page next to the password form, with its client from
 * the environment. trustEmail lets Google's verified address count as verified (OIDCIdentityProvider takes Google's
 * email_verified claim), which a "profiles" share link needs. A Google login whose address belongs to an existing
 * account goes through the realm's own first-login flow, which links only after the user confirms and signs in with
 * that account's password; the file may neither replace Keycloak's built-in flow nor add a step that links silently, and
 * no provider mapper may give Google users a role or an attribute.
 */
function checkGoogleLogin(realm: Realm, problems: string[]): void {
  const providers = list(realm["identityProviders"]);
  for (const other of providers.filter((provider) => !isRecord(provider) || provider["alias"] !== GOOGLE_PROVIDER)) {
    problems.push(`identity provider ${isRecord(other) ? String(other["alias"]) : "that is not an object"}: not allowed (the realm offers only "${GOOGLE_PROVIDER}"; another provider needs its own rule here first)`);
  }
  const googles = providers.filter(isRecord).filter((provider) => provider["alias"] === GOOGLE_PROVIDER);
  const [google] = googles;
  if (googles.length !== 1 || !google) {
    problems.push(`identity provider "${GOOGLE_PROVIDER}": exactly one is required (has: ${googles.length}); Google is the second way to log in, next to the password`);
    return;
  }
  const where = `identity provider "${GOOGLE_PROVIDER}"`;
  if (google["providerId"] !== "google") problems.push(`${where}: providerId must be "google" (Keycloak's Google provider sets Google's endpoints and issuer)`);
  if (google["enabled"] !== true) problems.push(`${where}: must be enabled`);
  if (google["trustEmail"] !== true) {
    problems.push(`${where}: trustEmail must be true (Google's verified address counts as verified; a "profiles" share link admits only a verified address)`);
  }
  if (google["hideOnLogin"] === true) problems.push(`${where}: hideOnLogin must be off (the login page offers Google next to the password form)`);
  if (google["linkOnly"] === true) problems.push(`${where}: linkOnly must be off (Google would only link accounts and never log anybody in)`);
  if (google["authenticateByDefault"] === true) {
    problems.push(`${where}: authenticateByDefault must be off (every login would be sent to Google, past the password form)`);
  }
  if (google["storeToken"] === true || google["addReadTokenRoleOnCreate"] === true) {
    problems.push(`${where}: Google's tokens are not kept (storeToken and addReadTokenRoleOnCreate off)`);
  }
  if (google["firstBrokerLoginFlowAlias"] !== CHANCE_FIRST_BROKER_LOGIN_FLOW) {
    problems.push(`${where}: firstBrokerLoginFlowAlias must be "${CHANCE_FIRST_BROKER_LOGIN_FLOW}" (it links an existing account only after that account's password, and the provider's address cannot be edited on the way; has: ${shown(google["firstBrokerLoginFlowAlias"])})`);
  }
  if (google["postBrokerLoginFlowAlias"] !== undefined && google["postBrokerLoginFlowAlias"] !== "") {
    problems.push(`${where}: no post broker login flow (has: ${shown(google["postBrokerLoginFlowAlias"])})`);
  }
  const config = isRecord(google["config"]) ? google["config"] : {};
  for (const [key, name] of Object.entries(GOOGLE_SETTINGS)) {
    if (config[key] !== `\${${name}}`) {
      const literal = config[key] !== undefined && !isPlaceholder(config[key]) ? "; a literal would put the Google client into a tracked file" : "";
      problems.push(`${where}: config.${key} must be the placeholder \${${name}}${literal}`);
    }
  }
  const scopes = typeof config["defaultScope"] === "string" ? config["defaultScope"].split(/\s+/).filter(Boolean).sort() : [];
  if (scopes.join(" ") !== [...GOOGLE_SCOPES].sort().join(" ")) {
    problems.push(`${where}: config.defaultScope must be exactly "${GOOGLE_SCOPES.join(" ")}" (has: ${shown(config["defaultScope"])})`);
  }
  if (config["syncMode"] !== GOOGLE_SYNC_MODE) {
    problems.push(`${where}: config.syncMode must be "${GOOGLE_SYNC_MODE}" (the profile is taken from Google at the first login only; FORCE would overwrite the address at every login)`);
  }
  for (const key of Object.keys(config)) {
    if (!GOOGLE_CONFIG_KEYS.includes(key)) problems.push(`${where}: config.${key} is not allowed (only ${GOOGLE_CONFIG_KEYS.join(", ")}; Keycloak sets Google's endpoints and issuer itself)`);
  }
  // One mapper only, the user name of Google users; any other mapper could give every Google user a role or an attribute.
  const mappers = list(realm["identityProviderMappers"]);
  const isUsernameMapper = (mapper: unknown): boolean => {
    if (!isRecord(mapper) || mapper["identityProviderAlias"] !== GOOGLE_PROVIDER || mapper["identityProviderMapper"] !== USERNAME_MAPPER) return false;
    const c = isRecord(mapper["config"]) ? mapper["config"] : {};
    return c["template"] === GOOGLE_USERNAME_TEMPLATE && (c["target"] === undefined || c["target"] === "LOCAL") && Object.keys(c).every((key) => ["template", "target", "syncMode"].includes(key));
  };
  for (const other of mappers.filter((mapper) => !isUsernameMapper(mapper))) {
    problems.push(`identity provider mapper ${describeMapper(other)}: not allowed (the only mapper is ${USERNAME_MAPPER} on "${GOOGLE_PROVIDER}" with the template ${GOOGLE_USERNAME_TEMPLATE}, target LOCAL); a mapper could give every Google user a role or an attribute`);
  }
  if (mappers.filter(isUsernameMapper).length !== 1) {
    problems.push(`identity provider "${GOOGLE_PROVIDER}": exactly one user name mapper (${USERNAME_MAPPER}, template ${GOOGLE_USERNAME_TEMPLATE}) is required, so a stranger's user name cannot catch a victim's first Google login`);
  }
  const flows = list(realm["authenticationFlows"]).filter(isRecord);
  if (flows.some((flow) => flow["alias"] === FIRST_BROKER_LOGIN_FLOW)) {
    problems.push(`authentication flow "${FIRST_BROKER_LOGIN_FLOW}": must not be defined in the file (it would replace Keycloak's built-in flow; the realm's own is "${CHANCE_FIRST_BROKER_LOGIN_FLOW}")`);
  }
  for (const flow of flows) {
    if (list(flow["authenticationExecutions"]).filter(isRecord).some((step) => step["authenticator"] === AUTO_LINK_STEP)) {
      problems.push(`authentication flow "${String(flow["alias"])}": the step ${AUTO_LINK_STEP} is not allowed (it links a provider's login to an existing account without asking its owner)`);
    }
  }
}

/**
 * "Forgot Password?": Keycloak's built-in reset flow mails a reset link to the account's address through the realm's mail
 * server, and the new password replaces any other. It is also how the owner of an address links Google to an account
 * whose password they do not know (the first-login flow asks for that password and offers the reset there).
 */
function checkPasswordReset(realm: Realm, problems: string[]): void {
  if (realm["registrationAllowed"] !== true) return;
  if (realm["resetPasswordAllowed"] !== true) {
    problems.push("resetPasswordAllowed must be true while users sign up with a password (the owner of an address takes back an account that someone else registered with it through the reset mail)");
  }
  if (realm["resetCredentialsFlow"] !== undefined && realm["resetCredentialsFlow"] !== RESET_CREDENTIALS_FLOW) {
    problems.push(`resetCredentialsFlow must be Keycloak's "${RESET_CREDENTIALS_FLOW}" (it mails the reset link to the account's address; has: ${shown(realm["resetCredentialsFlow"])})`);
  }
  if (list(realm["authenticationFlows"]).filter(isRecord).some((flow) => flow["alias"] === RESET_CREDENTIALS_FLOW)) {
    problems.push(`authentication flow "${RESET_CREDENTIALS_FLOW}": must not be defined in the file (it would replace Keycloak's built-in flow, which proves the address with a mailed link)`);
  }
}

/**
 * Keycloak stores a flow's, client's, role's and client scope's description in a column of 255 characters; a longer one
 * stops the server at the realm import ("value too long for type character varying(255)", seen 2026-11-12).
 */
export const MAX_DESCRIPTION = 255;
function checkDescriptions(realm: Realm, problems: string[]): void {
  const roles = isRecord(realm["roles"]) ? list(realm["roles"]["realm"]) : [];
  const named: [string, unknown[], string][] = [
    ["authentication flow", list(realm["authenticationFlows"]), "alias"],
    ["client", list(realm["clients"]), "clientId"],
    ["realm role", roles, "name"],
    ["client scope", list(realm["clientScopes"]), "name"],
  ];
  for (const [kind, items, key] of named) {
    for (const item of items.filter(isRecord)) {
      const description = item["description"];
      if (typeof description === "string" && description.length > MAX_DESCRIPTION) {
        problems.push(`${kind} ${String(item[key])}: the description has ${description.length} characters, at most ${MAX_DESCRIPTION} (Keycloak's column; a longer one stops the realm import)`);
      }
    }
  }
}

/** Returns every problem of the realm file; an empty list means it passes. */
export function checkRealm(realm: Realm): string[] {
  const problems: string[] = [];
  checkDescriptions(realm, problems);
  if (realm["realm"] !== "chance") problems.push('the realm must be called "chance"');
  if (realm["enabled"] !== true) problems.push("the realm must be enabled");
  if (realm["organizationsEnabled"] !== true) problems.push("organizations must be on (the tenant is an organization, ADR-033)");
  if (realm["sslRequired"] !== "external" && realm["sslRequired"] !== "all") problems.push("sslRequired must be external or all");
  if (realm["bruteForceProtected"] !== true) problems.push("brute-force protection must be on");
  if (typeof realm["passwordPolicy"] !== "string" || !/length\((1[2-9]|[2-9]\d)\)/.test(realm["passwordPolicy"])) {
    problems.push("the password policy must require at least 12 characters");
  }
  const lifespan = realm["accessTokenLifespan"];
  if (typeof lifespan !== "number" || lifespan > 900) problems.push("access tokens must live at most 15 minutes");
  checkEmailVerification(realm, problems);

  const roles = isRecord(realm["roles"]) ? list(realm["roles"]["realm"]).filter(isRecord).map((role) => role["name"]) : [];
  for (const role of REALM_ROLES) if (!roles.includes(role)) problems.push(`realm role "${role}" is missing`);
  checkRetiredRoles(realm, problems);
  checkOrganizationScope(realm, problems);

  const web = client(realm, "web");
  if (web) checkWebClient(web, problems);
  else problems.push('client "web" is missing');
  const tenants = client(realm, "tenants");
  if (tenants) checkTenantsClient(tenants, realm, problems);
  else problems.push('client "tenants" is missing');
  for (const [name, secret] of Object.entries(TOKEN_CLIENTS)) {
    const account = client(realm, name);
    if (account) checkTokenClient(name, secret, account, realm, problems);
    else problems.push(`client "${name}" is missing`);
  }
  for (const other of list(realm["clients"]).filter(isRecord)) {
    if (!(REALM_CLIENTS as readonly unknown[]).includes(other["clientId"])) {
      problems.push(`client ${String(other["clientId"])}: not an allowed client (allowed: ${REALM_CLIENTS.join(", ")})`);
    }
    if (typeof other["secret"] === "string" && !isPlaceholder(other["secret"])) {
      problems.push(`client ${String(other["clientId"])}: the secret must be a placeholder`);
    }
  }
  checkUsers(realm, problems);
  checkPlatformAdmin(realm, problems);
  checkRegistrationSetsPasswordAfterVerification(realm, problems);
  checkRequiredActions(realm, problems);
  checkLifespans(realm, problems);
  checkVerificationMail(realm, problems);
  checkPasswordReset(realm, problems);
  checkFirstBrokerLoginFlow(realm, problems);
  checkNoEmailChangeByMail(realm, problems);
  checkRealmAttributes(realm, problems);
  checkLocales(realm, problems);
  checkUserProfile(realm, problems);
  checkGoogleLogin(realm, problems);
  checkAdminClientsCarryNoAudience(realm, problems);

  const used = placeholdersIn(realm);
  for (const name of used) if (!REALM_PLACEHOLDERS.includes(name)) problems.push(`placeholder ${name} is not in REALM_PLACEHOLDERS`);
  for (const name of REALM_PLACEHOLDERS) if (!used.includes(name)) problems.push(`REALM_PLACEHOLDERS lists ${name}, which the realm does not use`);
  return problems;
}
