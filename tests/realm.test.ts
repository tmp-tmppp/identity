import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  ALWAYS_SET_PASSWORD,
  CHANCE_FIRST_BROKER_LOGIN_FLOW,
  EMAIL_CHANGE_WARNING,
  GOOGLE_USERNAME_TEMPLATE,
  UPDATE_EMAIL_LIFESPAN,
  FIRST_BROKER_LOGIN_FLOW,
  MAX_LIFESPANS,
  REQUIRED_ACTIONS,
  VERIFICATION_MAIL_WARNING,
  GOOGLE_SCOPES,
  GOOGLE_SETTINGS,
  PLATFORM_ADMIN,
  REALM_PLACEHOLDERS,
  REGISTRATION_FLOW,
  RESET_CREDENTIALS_FLOW,
  SMTP_SETTINGS,
  checkRealm,
  placeholdersIn,
} from "../src/realm-check.js";
import type { Realm } from "../src/realm-check.js";

const read = (file: string): string => readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
const realm = (): Realm => JSON.parse(read("realm/chance-realm.json")) as Realm;

type Json = Record<string, any>;
const clientOf = (r: Json, id: string): Json => r["clients"].find((c: Json) => c["clientId"] === id);
// The token mappers that a change may add to a client.
const audienceMapper = (audience: string): Json => ({
  name: `audience ${audience}`,
  protocol: "openid-connect",
  protocolMapper: "oidc-audience-mapper",
  consentRequired: false,
  config: { "included.custom.audience": audience, "access.token.claim": "true", "introspection.token.claim": "true", "id.token.claim": "false" },
});
const hardcodedRole = (role: string): Json => ({
  name: `hardcoded ${role}`,
  protocol: "openid-connect",
  protocolMapper: "oidc-hardcoded-role-mapper",
  consentRequired: false,
  config: { role },
});
const hardcodedOrganization = (): Json => ({
  name: "hardcoded organization",
  protocol: "openid-connect",
  protocolMapper: "oidc-hardcoded-claim-mapper",
  consentRequired: false,
  config: { "claim.name": "organization", "claim.value": "tenant-1", "jsonType.label": "String", "access.token.claim": "true" },
});
const mutated = (change: (r: Json) => void): string[] => {
  const copy: Json = realm();
  change(copy);
  return checkRealm(copy);
};

describe("the realm file", () => {
  it("passes every check", () => {
    expect(checkRealm(realm())).toEqual([]);
  });

  it("names only the documented placeholders", () => {
    expect(placeholdersIn(realm())).toEqual([...REALM_PLACEHOLDERS].sort());
  });
});

describe("the checks catch a weakened realm", () => {
  const cases: [string, (r: Json) => void, RegExp][] = [
    ["organizations off", (r) => (r["organizationsEnabled"] = false), /organizations must be on/],
    ["TLS not required", (r) => (r["sslRequired"] = "none"), /sslRequired/],
    ["no brute-force protection", (r) => (r["bruteForceProtected"] = false), /brute-force/],
    ["short passwords", (r) => (r["passwordPolicy"] = "length(8)"), /12 characters/],
    ["long-lived tokens", (r) => (r["accessTokenLifespan"] = 3600), /15 minutes/],
    ["a missing role", (r) => (r["roles"]["realm"] = r["roles"]["realm"].filter((x: Json) => x["name"] !== "platform-admin")), /"platform-admin" is missing/],
    ["a retired role as a default role", (r) => (r["defaultRole"] = { name: "default-roles-chance", composites: { realm: ["offline_access", "trader"] } }), /"trader" is a default role/],
    ["a retired role in the old default roles", (r) => (r["defaultRoles"] = ["tenant-admin"]), /"tenant-admin" is a default role/],
    [
      "a composite role that contains a retired role",
      (r) => r["roles"]["realm"].push({ name: "member", composites: { realm: ["trader"] } }),
      /realm role member: a composite that contains the retired role "trader"/,
    ],
    ["a retired role assigned to the platform admin", (r) => r["users"][1]["realmRoles"].push("tenant-admin"), /holds a retired tenant realm role/],
    ["no built-in client scopes", (r) => delete r["attributes"]["CreateDefaultClientScopes"], /CreateDefaultClientScopes must be "true"/],
    ["no organization scope", (r) => (r["clientScopes"] = []), /client scope "chance-organization" is missing/],
    ["another client scope in the file", (r) => r["clientScopes"].push({ name: "organization", protocol: "openid-connect" }), /client scope organization: not allowed/],
    ["no group mapper", (r) => (r["clientScopes"][0]["protocolMappers"] = r["clientScopes"][0]["protocolMappers"].slice(0, 1)), /exactly one organization group membership mapper/],
    ["no membership mapper", (r) => (r["clientScopes"][0]["protocolMappers"] = r["clientScopes"][0]["protocolMappers"].slice(1)), /exactly one organization membership mapper/],
    ["a hardcoded claim in the organization scope", (r) => r["clientScopes"][0]["protocolMappers"].push(hardcodedOrganization()), /client scope chance-organization: the protocol mapper "hardcoded organization"/],
    [
      "group role mappings on",
      (r) => (r["clientScopes"][0]["protocolMappers"][1]["config"]["addGroupRoleMappings"] = "true"),
      /group role mappings must be off/,
    ],
    [
      "groups left out of the access token",
      (r) => (r["clientScopes"][0]["protocolMappers"][1]["config"]["access.token.claim"] = "false"),
      /organization group membership mapper must write into the access token and the ID token/,
    ],
    [
      "groups left out of the ID token",
      (r) => delete r["clientScopes"][0]["protocolMappers"][1]["config"]["id.token.claim"],
      /organization group membership mapper must write into the access token and the ID token/,
    ],
    [
      "the organization claim under another name",
      (r) => (r["clientScopes"][0]["protocolMappers"][0]["config"]["claim.name"] = "orgs"),
      /membership mapper must write the claim "organization"/,
    ],
    [
      "the organization id in the claim",
      (r) => (r["clientScopes"][0]["protocolMappers"][0]["config"]["addOrganizationId"] = "true"),
      /adds neither the organization id nor its attributes/,
    ],
    ["the built-in organization scope on the web client", (r) => clientOf(r, "web")["defaultClientScopes"].push("organization"), /built-in client scope "organization" is not allowed/],
    ["the built-in organization scope as an optional one", (r) => clientOf(r, "web")["optionalClientScopes"].push("organization"), /built-in client scope "organization" is not allowed/],
    ["implicit flow on the web client", (r) => (clientOf(r, "web")["implicitFlowEnabled"] = true), /implicit flow/],
    ["password grant on the web client", (r) => (clientOf(r, "web")["directAccessGrantsEnabled"] = true), /password grants/],
    ["no PKCE", (r) => delete clientOf(r, "web")["attributes"]["pkce.code.challenge.method"], /PKCE/],
    ["a wildcard redirect", (r) => clientOf(r, "web")["redirectUris"].push("*"), /redirect URI/],
    ["a foreign web origin", (r) => clientOf(r, "web")["webOrigins"].push("https://evil.example"), /web origin/],
    ["no organization claim", (r) => (clientOf(r, "web")["defaultClientScopes"] = ["roles", "basic"]), /"chance-organization" is missing/],
    [
      "the organization scope only as an optional one",
      (r) => {
        clientOf(r, "web")["defaultClientScopes"] = ["roles", "basic"];
        clientOf(r, "web")["optionalClientScopes"] = ["chance-organization"];
      },
      /"chance-organization" must be one of its default client scopes/,
    ],
    ["no audience", (r) => (clientOf(r, "web")["protocolMappers"] = []), /audience mapper/],
    ["no admin API scope for the service account", (r) => (clientOf(r, "tenants")["defaultClientScopes"] = ["basic", "roles"]), /kc-admin-api" is missing/],
    ["profile data in the service token", (r) => clientOf(r, "tenants")["defaultClientScopes"].push("profile"), /only basic, roles and kc-admin-api/],
    ["offline tokens for the web client", (r) => clientOf(r, "web")["optionalClientScopes"].push("offline_access"), /offline_access" is not allowed/],
    ["admin API scope on the web client", (r) => clientOf(r, "web")["optionalClientScopes"].push("kc-admin-api"), /not allowed/],
    ["a literal client secret", (r) => (clientOf(r, "tenants")["secret"] = "hunter2hunter2"), /placeholder/],
    ["a public tenants client", (r) => (clientOf(r, "tenants")["publicClient"] = true), /confidential/],
    ["a browser login for the service account", (r) => (clientOf(r, "tenants")["standardFlowEnabled"] = true), /standardFlowEnabled must be off/],
    [
      "too many admin roles",
      (r) => r["users"].find((u: Json) => u["serviceAccountClientId"] === "tenants")["clientRoles"]["realm-management"].push("realm-admin"),
      /must hold exactly/,
    ],
    [
      "a realm role on the service account",
      (r) => (r["users"].find((u: Json) => u["serviceAccountClientId"] === "tenants")["realmRoles"] = ["platform-admin"]),
      /no other roles/,
    ],
    ["a missing payments client", (r) => (r["clients"] = r["clients"].filter((c: Json) => c["clientId"] !== "payments")), /client "payments" is missing/],
    ["a public payments client", (r) => (clientOf(r, "payments")["publicClient"] = true), /payments: must be a confidential client/],
    ["no secret login for payments", (r) => (clientOf(r, "payments")["clientAuthenticatorType"] = "client-jwt"), /payments: the client must log in with its secret/],
    ["no service account for payments", (r) => (clientOf(r, "payments")["serviceAccountsEnabled"] = false), /payments: the service account must be on/],
    ["a browser login for payments", (r) => (clientOf(r, "payments")["standardFlowEnabled"] = true), /payments: standardFlowEnabled must be off/],
    ["the implicit flow for payments", (r) => (clientOf(r, "payments")["implicitFlowEnabled"] = true), /payments: implicitFlowEnabled must be off/],
    ["password grants for payments", (r) => (clientOf(r, "payments")["directAccessGrantsEnabled"] = true), /payments: directAccessGrantsEnabled must be off/],
    ["a literal payments secret", (r) => (clientOf(r, "payments")["secret"] = "hunter2hunter2"), /payments: the client secret must be the placeholder/],
    ["the tenants secret on payments", (r) => (clientOf(r, "payments")["secret"] = "${TENANTS_CLIENT_SECRET}"), /payments: the client secret must be the placeholder/],
    ["the admin API scope on payments", (r) => clientOf(r, "payments")["defaultClientScopes"].push("kc-admin-api"), /payments: "kc-admin-api" is not allowed/],
    ["the admin API scope as an optional one on payments", (r) => (clientOf(r, "payments")["optionalClientScopes"] = ["kc-admin-api"]), /payments: "kc-admin-api" is not allowed/],
    ["profile data in the payments token", (r) => clientOf(r, "payments")["defaultClientScopes"].push("profile"), /payments: default client scopes are exactly basic and roles/],
    ["no roles scope on payments", (r) => (clientOf(r, "payments")["defaultClientScopes"] = ["basic"]), /payments: default client scopes are exactly basic and roles/],
    ["an optional scope on payments", (r) => (clientOf(r, "payments")["optionalClientScopes"] = ["email"]), /payments: no optional client scopes/],
    ["no audience for payments", (r) => (clientOf(r, "payments")["protocolMappers"] = []), /payments: an audience mapper/],
    [
      "another audience for payments",
      (r) => (clientOf(r, "payments")["protocolMappers"][0]["config"]["included.custom.audience"] = "other"),
      /payments: an audience mapper/,
    ],
    [
      "a hardcoded platform-admin role on payments",
      (r) => clientOf(r, "payments")["protocolMappers"].push(hardcodedRole("platform-admin")),
      /payments: the protocol mapper "hardcoded platform-admin" \(oidc-hardcoded-role-mapper\) is not allowed/,
    ],
    [
      "a hardcoded organization claim on payments",
      (r) => clientOf(r, "payments")["protocolMappers"].push(hardcodedOrganization()),
      /payments: the protocol mapper "hardcoded organization" \(oidc-hardcoded-claim-mapper\) is not allowed/,
    ],
    [
      "a second audience mapper (realm-management) on payments",
      (r) => clientOf(r, "payments")["protocolMappers"].push(audienceMapper("realm-management")),
      /payments: exactly one audience mapper is allowed \(has: 2\)/,
    ],
    [
      "an audience mapper that adds a client audience on payments",
      (r) => (clientOf(r, "payments")["protocolMappers"][0]["config"]["included.client.audience"] = "realm-management"),
      /payments: the audience mapper names only the custom audience "chance", no client audience/,
    ],
    [
      "a hardcoded role instead of the audience mapper on payments",
      (r) => (clientOf(r, "payments")["protocolMappers"] = [hardcodedRole("platform-admin")]),
      /payments: an audience mapper must put "chance"/,
    ],
    [
      "an audience mapper that leaves the access token out on payments",
      (r) => (clientOf(r, "payments")["protocolMappers"][0]["config"]["access.token.claim"] = "false"),
      /payments: an audience mapper must put "chance" into the access token/,
    ],
    ["an audience mapper on tenants", (r) => (clientOf(r, "tenants")["protocolMappers"] = [audienceMapper("chance")]), /tenants: no protocol mappers are allowed \(has: "audience chance" \(oidc-audience-mapper\)\)/],
    [
      "a hardcoded role on tenants",
      (r) => (clientOf(r, "tenants")["protocolMappers"] = [hardcodedRole("platform-admin")]),
      /tenants: no protocol mappers are allowed \(has: "hardcoded platform-admin" \(oidc-hardcoded-role-mapper\)\)/,
    ],
    [
      "a hardcoded platform-admin role on the web client",
      (r) => clientOf(r, "web")["protocolMappers"].push(hardcodedRole("platform-admin")),
      /web: the protocol mapper "hardcoded platform-admin" \(oidc-hardcoded-role-mapper\) is not allowed/,
    ],
    [
      "a hardcoded organization claim on the web client",
      (r) => clientOf(r, "web")["protocolMappers"].push(hardcodedOrganization()),
      /web: the protocol mapper "hardcoded organization" \(oidc-hardcoded-claim-mapper\) is not allowed/,
    ],
    [
      "a second audience mapper on the web client",
      (r) => clientOf(r, "web")["protocolMappers"].push(audienceMapper("realm-management")),
      /web: exactly one audience mapper is allowed \(has: 2\)/,
    ],
    [
      "an audience mapper that leaves the access token out on the web client",
      (r) => (clientOf(r, "web")["protocolMappers"][0]["config"]["access.token.claim"] = "false"),
      /web: an audience mapper must put "chance" into the access token/,
    ],
    [
      "an admin role on the payments account",
      (r) => r["users"].push({ username: "service-account-payments", serviceAccountClientId: "payments", clientRoles: { "realm-management": ["view-users"] } }),
      /payments: the service account holds no realm role and no admin role/,
    ],
    [
      "a realm role on the payments account",
      (r) => r["users"].push({ username: "service-account-payments", serviceAccountClientId: "payments", realmRoles: ["trader"] }),
      /payments: the service account holds no realm role and no admin role/,
    ],
    [
      "a client nobody listed",
      (r) => r["clients"].push({ clientId: "extra", publicClient: false, secret: "${TENANTS_CLIENT_SECRET}" }),
      /client extra: not an allowed client/,
    ],
    ["a missing tenants-markets client", (r) => (r["clients"] = r["clients"].filter((c: Json) => c["clientId"] !== "tenants-markets")), /client "tenants-markets" is missing/],
    ["no audience for tenants-markets", (r) => (clientOf(r, "tenants-markets")["protocolMappers"] = []), /tenants-markets: an audience mapper/],
    ["the tenants secret on tenants-markets", (r) => (clientOf(r, "tenants-markets")["secret"] = "${TENANTS_CLIENT_SECRET}"), /tenants-markets: the client secret must be the placeholder/],
    ["the admin API scope on tenants-markets", (r) => clientOf(r, "tenants-markets")["defaultClientScopes"].push("kc-admin-api"), /tenants-markets: "kc-admin-api" is not allowed/],
    [
      "an admin role on the tenants-markets account",
      (r) => r["users"].push({ username: "service-account-tenants-markets", serviceAccountClientId: "tenants-markets", clientRoles: { "realm-management": ["view-users"] } }),
      /tenants-markets: the service account holds no realm role and no admin role/,
    ],
    [
      "an audience mapper on a client with admin roles",
      (r) => (clientOf(r, "tenants")["protocolMappers"] = [audienceMapper("chance")]),
      /tenants: a client whose service account holds admin roles must not carry an audience mapper/,
    ],
    ["a literal password", (r) => (r["users"][1]["credentials"][0]["value"] = "Secret-password-1"), /credential value/],
    ["a permanent imported password", (r) => (r["users"][1]["credentials"][0]["temporary"] = false), /temporary/],
    ["no forced password change", (r) => delete r["users"][1]["requiredActions"], /UPDATE_PASSWORD/],
    ["a second platform admin", (r) => r["users"].push({ username: "x", realmRoles: ["platform-admin"] }), /exactly one platform admin/],
    ["an undocumented placeholder", (r) => (r["displayName"] = "${SOMETHING_NEW}"), /SOMETHING_NEW is not in REALM_PLACEHOLDERS/],
    ["a missing web client", (r) => (r["clients"] = r["clients"].filter((c: Json) => c["clientId"] !== "web")), /client "web" is missing/],
  ];

  it.each(cases)("%s", (_name, change, expected) => {
    const problems = mutated(change);
    expect(problems.some((problem) => expected.test(problem)), problems.join("\n")).toBe(true);
  });
});

describe("the service accounts that only get tokens", () => {
  const accounts: [string, string][] = [
    ["payments", "PAYMENTS_CLIENT_SECRET"],
    ["market-maker", "MARKET_MAKER_CLIENT_SECRET"],
    ["markets", "MARKETS_CLIENT_SECRET"],
  ];
  const mutations: [string, (c: Json) => void, RegExp][] = [
    ["a public client", (c) => (c["publicClient"] = true), /: must be a confidential client/],
    ["a browser login", (c) => (c["standardFlowEnabled"] = true), /: standardFlowEnabled must be off/],
    ["password grants", (c) => (c["directAccessGrantsEnabled"] = true), /: directAccessGrantsEnabled must be off/],
    ["the admin API scope", (c) => c["defaultClientScopes"].push("kc-admin-api"), /: "kc-admin-api" is not allowed/],
    ["profile data", (c) => c["defaultClientScopes"].push("profile"), /: default client scopes are exactly basic and roles/],
    ["no audience", (c) => (c["protocolMappers"] = []), /: an audience mapper must put "chance"/],
    ["another audience", (c) => (c["protocolMappers"][0]["config"]["included.custom.audience"] = "other"), /: an audience mapper must put "chance"/],
    ["a hardcoded platform-admin role", (c) => c["protocolMappers"].push(hardcodedRole("platform-admin")), /: the protocol mapper "hardcoded platform-admin"/],
    ["a literal secret", (c) => (c["secret"] = "hunter2hunter2"), /: the client secret must be the placeholder/],
  ];

  it("exist, each with its own secret placeholder", () => {
    for (const [id, placeholder] of accounts) {
      expect(clientOf(realm(), id)?.["secret"], id).toBe(`\${${placeholder}}`);
    }
  });

  it.each(accounts.flatMap(([id]) => mutations.map(([name, change, expected]) => [id, name, change, expected] as const)))(
    "%s: %s",
    (id, _name, change, expected) => {
      const problems = mutated((r) => change(clientOf(r, id)));
      expect(problems.some((problem) => problem.startsWith(`${id}: `) && expected.test(problem)), problems.join("\n")).toBe(true);
    },
  );

  it("takes another client's secret as a mistake", () => {
    const problems = mutated((r) => (clientOf(r, "markets")["secret"] = "${MARKET_MAKER_CLIENT_SECRET}"));
    expect(problems.some((problem) => /markets: the client secret must be the placeholder/.test(problem))).toBe(true);
  });

  it.each(accounts.map(([id]) => id))("%s is missing", (id) => {
    expect(mutated((r) => (r["clients"] = r["clients"].filter((c: Json) => c["clientId"] !== id)))).toContain(`client "${id}" is missing`);
  });
});

describe("e-mail verification", () => {
  it("is on, with every mail server setting read from the environment", () => {
    const r: Json = realm();
    expect(r["verifyEmail"]).toBe(true);
    for (const [key, name] of Object.entries(SMTP_SETTINGS)) {
      expect(r["smtpServer"][key], key).toBe(`\${${name}}`);
      expect(REALM_PLACEHOLDERS, name).toContain(name);
    }
    expect(r["smtpServer"]["fromDisplayName"]).toBe("Chance");
  });

  const cases: [string, (r: Json) => void, RegExp][] = [
    ["verifyEmail off", (r) => (r["verifyEmail"] = false), /^verifyEmail must be on/],
    ["verifyEmail left out", (r) => delete r["verifyEmail"], /^verifyEmail must be on/],
    ["verifyEmail as a string", (r) => (r["verifyEmail"] = "true"), /^verifyEmail must be on/],
    ["no mail server", (r) => delete r["smtpServer"], /^smtpServer is missing/],
    ["a mail server that is not an object", (r) => (r["smtpServer"] = "${SMTP_HOST}"), /^smtpServer is missing/],
    ["a literal host", (r) => (r["smtpServer"]["host"] = "smtp.example.com"), /^smtpServer: host must be the placeholder \$\{SMTP_HOST\}; a literal/],
    ["a literal login", (r) => (r["smtpServer"]["user"] = "mailer"), /^smtpServer: user must be the placeholder \$\{SMTP_USER\}; a literal/],
    ["a literal password", (r) => (r["smtpServer"]["password"] = "hunter2hunter2"), /^smtpServer: password must be the placeholder \$\{SMTP_PASSWORD\}; a literal/],
    ["no password", (r) => delete r["smtpServer"]["password"], /^smtpServer: password must be the placeholder \$\{SMTP_PASSWORD\}/],
    ["the login as the password", (r) => (r["smtpServer"]["password"] = "${SMTP_USER}"), /^smtpServer: password must be the placeholder \$\{SMTP_PASSWORD\}$/],
    ["a literal sender", (r) => (r["smtpServer"]["from"] = "no-reply@example.com"), /^smtpServer: from must be the placeholder \$\{SMTP_FROM\}$/],
    ["a fixed port", (r) => (r["smtpServer"]["port"] = "587"), /^smtpServer: port must be the placeholder \$\{SMTP_PORT\}$/],
    ["a fixed STARTTLS", (r) => (r["smtpServer"]["starttls"] = "true"), /^smtpServer: starttls must be the placeholder \$\{SMTP_STARTTLS\}$/],
    ["a fixed TLS", (r) => (r["smtpServer"]["ssl"] = "false"), /^smtpServer: ssl must be the placeholder \$\{SMTP_SSL\}$/],
    ["a fixed login switch", (r) => (r["smtpServer"]["auth"] = "false"), /^smtpServer: auth must be the placeholder \$\{SMTP_AUTH\}$/],
    ["a further key with a literal secret", (r) => Object.assign(r["smtpServer"], { authType: "token", authTokenClientSecret: "not-a-placeholder" }), /^smtpServer: authTokenClientSecret is not allowed/],
    ["the mail debug log", (r) => (r["smtpServer"]["debug"] = "true"), /^smtpServer: debug is not allowed/],
    ["a further key even as a placeholder", (r) => (r["smtpServer"]["replyTo"] = "${SMTP_FROM}"), /^smtpServer: replyTo is not allowed/],
  ];

  it.each(cases)("fails on %s", (_name, change, expected) => {
    const problems = mutated(change);
    expect(problems.some((problem) => expected.test(problem)), problems.join("\n")).toBe(true);
  });

  it("names a literal host, login or password as a leak, but not a placeholder of another setting", () => {
    expect(mutated((r) => (r["smtpServer"]["host"] = "${SMTP_FROM}"))).toContain("smtpServer: host must be the placeholder ${SMTP_HOST}");
  });
});

describe("sign-up sets the password only after the mail link", () => {
  const flowOf = (r: Json, alias: string): Json => r["authenticationFlows"].find((f: Json) => f["alias"] === alias);
  const formOf = (r: Json): Json => flowOf(r, flowOf(r, REGISTRATION_FLOW)["authenticationExecutions"][0]["flowAlias"]);
  const passwordStep = (r: Json): Json => formOf(r)["authenticationExecutions"].find((e: Json) => e["authenticator"] === "registration-password-action");
  // The option that puts the password on the form, before the address is verified (T3 in the README's threat table).
  const passwordOnForm = (value: unknown) => (r: Json) => {
    r["authenticatorConfig"] = [{ alias: "password on the form", config: { [ALWAYS_SET_PASSWORD]: value } }];
    passwordStep(r)["authenticatorConfig"] = "password on the form";
  };

  it("on the realm's own form, with the password step required and no option that puts the password on the form", () => {
    const r: Json = realm();
    expect(r["registrationAllowed"]).toBe(true);
    expect(r["verifyEmail"]).toBe(true);
    expect(r["registrationFlow"]).toBe(REGISTRATION_FLOW);
    expect(passwordStep(r)["requirement"]).toBe("REQUIRED");
    expect(passwordStep(r)["authenticatorConfig"]).toBeUndefined();
    expect(JSON.stringify(r)).not.toContain(ALWAYS_SET_PASSWORD);
  });

  const cases: [string, (r: Json) => void, RegExp][] = [
    ["Keycloak's built-in flow (no registrationFlow)", (r) => delete r["registrationFlow"], /registration flow "registration": not defined in the file, so the file does not state its steps/],
    ["Keycloak's built-in flow by name", (r) => (r["registrationFlow"] = "registration"), /registration flow "registration": not defined in the file/],
    ["the file's flows left out", (r) => delete r["authenticationFlows"], /registration flow "chance registration": not defined in the file/],
    ["the password on the form (the option on)", passwordOnForm("true"), new RegExp(`the password step must not set ${ALWAYS_SET_PASSWORD} \\(a password chosen on the form before the address is verified`)],
    ["the option as a boolean", passwordOnForm(true), new RegExp(`must not set ${ALWAYS_SET_PASSWORD}`)],
    ["the option in capitals", passwordOnForm("TRUE"), new RegExp(`must not set ${ALWAYS_SET_PASSWORD}`)],
    ["the password step disabled", (r) => (passwordStep(r)["requirement"] = "DISABLED"), /the sign-up form must hold the password step registration-password-action once, REQUIRED/],
    [
      "no password step",
      (r) => (formOf(r)["authenticationExecutions"] = formOf(r)["authenticationExecutions"].filter((e: Json) => e["authenticator"] !== "registration-password-action")),
      /the sign-up form must hold the password step/,
    ],
    ["a second password step", (r) => formOf(r)["authenticationExecutions"].push({ ...passwordStep(r), authenticatorConfig: undefined, priority: 80 }), /the sign-up form must hold the password step registration-password-action once/],
    ["the form as a plain flow", (r) => (formOf(r)["providerId"] = "basic-flow"), /must be a form flow \(form-flow\) defined in the file/],
    ["the form not in the file", (r) => (flowOf(r, REGISTRATION_FLOW)["authenticationExecutions"][0]["flowAlias"] = "registration form"), /the sign-up form "registration form" must be a form flow/],
    ["the form optional", (r) => (flowOf(r, REGISTRATION_FLOW)["authenticationExecutions"][0]["requirement"] = "ALTERNATIVE"), /must hold exactly one step, the required sign-up form/],
    [
      "a second step next to the form",
      (r) => flowOf(r, REGISTRATION_FLOW)["authenticationExecutions"].push({ authenticator: "idp-auto-link", authenticatorFlow: false, requirement: "ALTERNATIVE", priority: 20 }),
      /must hold exactly one step, the required sign-up form/,
    ],
  ];

  it.each(cases)("fails on %s", (_name, change, expected) => {
    const problems = mutated(change);
    expect(problems.some((problem) => expected.test(problem)), problems.join("\n")).toBe(true);
  });

  it("refuses the option with verifyEmail off too, and requires verifyEmail", () => {
    const problems = mutated((r) => {
      r["verifyEmail"] = false;
      passwordOnForm("true")(r);
    });
    expect(problems.some((problem) => problem.includes(`must not set ${ALWAYS_SET_PASSWORD}`))).toBe(true);
    expect(problems.some((problem) => problem.startsWith("verifyEmail must be on"))).toBe(true);
  });

  it("checks nothing of the flow when sign-up is off", () => {
    expect(mutated((r) => {
      r["registrationAllowed"] = false;
      delete r["registrationFlow"];
    })).toEqual([]);
  });
});

describe("password reset", () => {
  it("is on, through Keycloak's own reset flow, while users sign up with a password", () => {
    const r: Json = realm();
    expect(r["registrationAllowed"]).toBe(true);
    expect(r["resetPasswordAllowed"]).toBe(true);
    expect(r["resetCredentialsFlow"]).toBeUndefined();
    expect(r["authenticationFlows"].map((f: Json) => f["alias"])).not.toContain(RESET_CREDENTIALS_FLOW);
  });

  const cases: [string, (r: Json) => void, RegExp][] = [
    ["reset off", (r) => (r["resetPasswordAllowed"] = false), /^resetPasswordAllowed must be true while users sign up with a password/],
    ["reset left out", (r) => delete r["resetPasswordAllowed"], /^resetPasswordAllowed must be true/],
    ["reset as a string", (r) => (r["resetPasswordAllowed"] = "true"), /^resetPasswordAllowed must be true/],
    ["another reset flow bound", (r) => (r["resetCredentialsFlow"] = "chance registration"), /^resetCredentialsFlow must be Keycloak's "reset credentials" .*has: chance registration\)$/],
    [
      "the reset flow replaced by the file",
      (r) => r["authenticationFlows"].push({ alias: RESET_CREDENTIALS_FLOW, providerId: "basic-flow", topLevel: true, builtIn: false, authenticationExecutions: [] }),
      /^authentication flow "reset credentials": must not be defined in the file/,
    ],
  ];

  it.each(cases)("fails on %s", (_name, change, expected) => {
    const problems = mutated(change);
    expect(problems.some((problem) => expected.test(problem)), problems.join("\n")).toBe(true);
  });

  it("is not required while sign-up is off", () => {
    expect(mutated((r) => {
      r["registrationAllowed"] = false;
      r["resetPasswordAllowed"] = false;
    })).toEqual([]);
  });
});

describe("Google login", () => {
  const googleOf = (r: Json): Json => r["identityProviders"].find((p: Json) => p["alias"] === "google");
  const githubProvider = (): Json => ({ alias: "github", providerId: "github", enabled: true, config: { clientId: "${GOOGLE_CLIENT_ID}", clientSecret: "${GOOGLE_CLIENT_SECRET}" } });

  it("is offered next to the password form, with the client from the environment and Google's verified address trusted", () => {
    const google = googleOf(realm());
    expect(google).toMatchObject({ providerId: "google", enabled: true, trustEmail: true, hideOnLogin: false, linkOnly: false, authenticateByDefault: false, storeToken: false });
    expect(google["firstBrokerLoginFlowAlias"]).toBe(CHANCE_FIRST_BROKER_LOGIN_FLOW);
    for (const [key, name] of Object.entries(GOOGLE_SETTINGS)) {
      expect(google["config"][key], key).toBe(`\${${name}}`);
      expect(REALM_PLACEHOLDERS, name).toContain(name);
    }
    expect(google["config"]["defaultScope"].split(" ").sort()).toEqual([...GOOGLE_SCOPES].sort());
    expect(realm()["identityProviderMappers"]).toEqual([
      { name: "google user name", identityProviderAlias: "google", identityProviderMapper: "oidc-username-idp-mapper", config: { template: GOOGLE_USERNAME_TEMPLATE, target: "LOCAL", syncMode: "IMPORT" } },
    ]);
  });

  const cases: [string, (r: Json) => void, RegExp][] = [
    ["no provider", (r) => delete r["identityProviders"], /^identity provider "google": exactly one is required \(has: 0\)/],
    ["Google twice", (r) => r["identityProviders"].push({ ...googleOf(r) }), /^identity provider "google": exactly one is required \(has: 2\)/],
    ["another provider next to Google", (r) => r["identityProviders"].push(githubProvider()), /^identity provider github: not allowed/],
    ["Google through the generic OIDC provider", (r) => (googleOf(r)["providerId"] = "oidc"), /^identity provider "google": providerId must be "google"/],
    ["Google disabled", (r) => (googleOf(r)["enabled"] = false), /^identity provider "google": must be enabled$/],
    ["Google's address not trusted", (r) => (googleOf(r)["trustEmail"] = false), /^identity provider "google": trustEmail must be true/],
    ["trustEmail left out", (r) => delete googleOf(r)["trustEmail"], /^identity provider "google": trustEmail must be true/],
    ["Google hidden on the login page", (r) => (googleOf(r)["hideOnLogin"] = true), /^identity provider "google": hideOnLogin must be off/],
    ["Google for linking only", (r) => (googleOf(r)["linkOnly"] = true), /^identity provider "google": linkOnly must be off/],
    ["every login sent to Google", (r) => (googleOf(r)["authenticateByDefault"] = true), /^identity provider "google": authenticateByDefault must be off/],
    ["Google's tokens stored", (r) => (googleOf(r)["storeToken"] = true), /^identity provider "google": Google's tokens are not kept/],
    ["the realm's first-login flow left out", (r) => delete googleOf(r)["firstBrokerLoginFlowAlias"], /^identity provider "google": firstBrokerLoginFlowAlias must be "chance first broker login" .*has: none\)$/],
    ["Keycloak's built-in first-login flow (review page and mailed link)", (r) => (googleOf(r)["firstBrokerLoginFlowAlias"] = FIRST_BROKER_LOGIN_FLOW), /firstBrokerLoginFlowAlias must be "chance first broker login" .*has: first broker login\)$/],
    ["another first-login flow", (r) => (googleOf(r)["firstBrokerLoginFlowAlias"] = "chance registration"), /firstBrokerLoginFlowAlias must be "chance first broker login" .*has: chance registration\)$/],
    ["a post-login flow", (r) => (googleOf(r)["postBrokerLoginFlowAlias"] = "browser"), /^identity provider "google": no post broker login flow \(has: browser\)$/],
    ["a literal client id", (r) => (googleOf(r)["config"]["clientId"] = "1234-abc.apps.example.com"), /^identity provider "google": config\.clientId must be the placeholder \$\{GOOGLE_CLIENT_ID\}; a literal/],
    ["a literal client secret", (r) => (googleOf(r)["config"]["clientSecret"] = "hunter2hunter2"), /^identity provider "google": config\.clientSecret must be the placeholder \$\{GOOGLE_CLIENT_SECRET\}; a literal/],
    ["no client secret", (r) => delete googleOf(r)["config"]["clientSecret"], /^identity provider "google": config\.clientSecret must be the placeholder \$\{GOOGLE_CLIENT_SECRET\}$/],
    ["the client id as the secret", (r) => (googleOf(r)["config"]["clientSecret"] = "${GOOGLE_CLIENT_ID}"), /^identity provider "google": config\.clientSecret must be the placeholder \$\{GOOGLE_CLIENT_SECRET\}$/],
    ["another client's secret", (r) => (googleOf(r)["config"]["clientSecret"] = "${TENANTS_CLIENT_SECRET}"), /^identity provider "google": config\.clientSecret must be the placeholder \$\{GOOGLE_CLIENT_SECRET\}$/],
    ["no config", (r) => delete googleOf(r)["config"], /^identity provider "google": config\.clientId must be the placeholder/],
    ["the address left out of the scopes", (r) => (googleOf(r)["config"]["defaultScope"] = "openid profile"), /^identity provider "google": config\.defaultScope must be exactly "openid email profile" \(has: openid profile\)$/],
    ["offline access on top", (r) => (googleOf(r)["config"]["defaultScope"] = "openid email profile offline_access"), /config\.defaultScope must be exactly "openid email profile"/],
    ["no scopes", (r) => delete googleOf(r)["config"]["defaultScope"], /config\.defaultScope must be exactly "openid email profile" \(has: none\)$/],
    ["the profile overwritten at every login", (r) => (googleOf(r)["config"]["syncMode"] = "FORCE"), /^identity provider "google": config\.syncMode must be "IMPORT"/],
    ["a foreign issuer", (r) => (googleOf(r)["config"]["issuer"] = "https://accounts.example.com"), /^identity provider "google": config\.issuer is not allowed/],
    ["a refresh token from Google", (r) => (googleOf(r)["config"]["offlineAccess"] = "true"), /^identity provider "google": config\.offlineAccess is not allowed/],
    [
      "a mapper that gives Google users a role",
      (r) => r["identityProviderMappers"].push({ name: "platform admins", identityProviderAlias: "google", identityProviderMapper: "oidc-hardcoded-role-idp-mapper", config: { role: "platform-admin" } }),
      /^identity provider mapper "platform admins" \(undefined\): not allowed|^identity provider mapper .*platform admins.*: not allowed/,
    ],
    [
      "the first-login flow replaced by the file",
      (r) => r["authenticationFlows"].push({ alias: FIRST_BROKER_LOGIN_FLOW, providerId: "basic-flow", topLevel: true, builtIn: false, authenticationExecutions: [] }),
      /^authentication flow "first broker login": must not be defined in the file/,
    ],
    ["Keycloak's first-login flow as the realm's default", (r) => (r["firstBrokerLoginFlow"] = FIRST_BROKER_LOGIN_FLOW), /^firstBrokerLoginFlow must be "chance first broker login" .*has: first broker login\)$/],
    ["no default first-login flow for the realm", (r) => delete r["firstBrokerLoginFlow"], /^firstBrokerLoginFlow must be "chance first broker login" .*has: none\)$/],
    [
      "a flow that links silently",
      (r) => r["authenticationFlows"].push({ alias: "silent link", providerId: "basic-flow", topLevel: true, builtIn: false, authenticationExecutions: [{ authenticator: "idp-auto-link", requirement: "REQUIRED", priority: 10 }] }),
      /^authentication flow "silent link": the step idp-auto-link is not allowed/,
    ],
  ];

  it.each(cases)("fails on %s", (_name, change, expected) => {
    const problems = mutated(change);
    expect(problems.some((problem) => expected.test(problem)), problems.join("\n")).toBe(true);
  });

  it("is a client id in the chart's ConfigMap that the schema requires and a secret that it refuses there; compose.yaml holds local placeholders", () => {
    const compose = read("compose.yaml");
    expect(compose).toMatch(/^\s+GOOGLE_CLIENT_ID: \S+\.apps\.googleusercontent\.com # hooks:allow local development only$/m);
    expect(compose).toMatch(/^\s+GOOGLE_CLIENT_SECRET: \S+ # hooks:allow local development only$/m);
    const schema = JSON.parse(read("helm/values.schema.json")) as Json;
    expect(schema["properties"]["env"]["required"]).toContain("GOOGLE_CLIENT_ID");
    expect(schema["properties"]["env"]["propertyNames"]["not"]["enum"]).not.toContain("GOOGLE_CLIENT_ID");
    expect(schema["properties"]["env"]["propertyNames"]["not"]["enum"]).toContain("GOOGLE_CLIENT_SECRET");
    expect(schema["properties"]["env"]["required"]).not.toContain("GOOGLE_CLIENT_SECRET");
    expect(read("helm/values.yaml")).toMatch(/^ {2}GOOGLE_CLIENT_ID: ""$/m);
    expect(read("helm/values-prod.yaml")).toMatch(/^ {2}GOOGLE_CLIENT_ID: ""$/m);
  });
});

// The scenarios T1 to T9 of the README's "Account takeover protections": each rule here fails on the realm change
// that would reopen one of them.
describe("account takeover protections", () => {
  const flowOf = (r: Json, alias: string): Json => r["authenticationFlows"].find((f: Json) => f["alias"] === alias);
  const linkExisting = (r: Json): Json => flowOf(r, "chance first broker login link existing");
  const createOrLink = (r: Json): Json => flowOf(r, "chance first broker login create or link");
  const stepIn = (flow: Json, authenticator: string): Json => flow["authenticationExecutions"].find((e: Json) => e["authenticator"] === authenticator);
  const action = (r: Json, alias: string): Json => r["requiredActions"].find((a: Json) => a["alias"] === alias);

  it("binds the realm's own first-login flow: a new account, or the existing one only after its password", () => {
    const r: Json = realm();
    expect(r["firstBrokerLoginFlow"]).toBe(CHANCE_FIRST_BROKER_LOGIN_FLOW);
    expect(r["identityProviders"].every((p: Json) => p["firstBrokerLoginFlowAlias"] === CHANCE_FIRST_BROKER_LOGIN_FLOW)).toBe(true);
    expect(createOrLink(r)["authenticationExecutions"].map((e: Json) => [e["authenticator"] ?? e["flowAlias"], e["requirement"]])).toEqual([
      ["idp-create-user-if-unique", "ALTERNATIVE"],
      ["chance first broker login link existing", "ALTERNATIVE"],
    ]);
    expect(linkExisting(r)["authenticationExecutions"].map((e: Json) => [e["authenticator"] ?? e["flowAlias"], e["requirement"]])).toEqual([
      ["idp-confirm-link", "REQUIRED"],
      ["idp-username-password-form", "REQUIRED"],
      ["chance first broker login second factor", "CONDITIONAL"],
    ]);
    expect(JSON.stringify(r)).not.toMatch(/idp-review-profile|idp-email-verification|idp-auto-link/);
  });

  it("lists every required action, UPDATE_EMAIL on, and VERIFY_EMAIL before UPDATE_PASSWORD", () => {
    const r: Json = realm();
    for (const alias of REQUIRED_ACTIONS) expect(action(r, alias), alias).toMatchObject({ providerId: alias, enabled: true });
    expect(action(r, "VERIFY_EMAIL")["priority"]).toBeLessThan(action(r, "UPDATE_PASSWORD")["priority"]);
  });

  it("keeps login pages, required action pages and mailed links short-lived, and warns in the verification mail", () => {
    const r: Json = realm();
    for (const [key, max] of Object.entries(MAX_LIFESPANS)) expect(r[key], key).toBeLessThanOrEqual(max);
    expect(r["localizationTexts"]["en"]["emailVerificationBody"]).toContain(VERIFICATION_MAIL_WARNING);
    expect(r["localizationTexts"]["en"]["emailVerificationBodyHtml"]).toContain(VERIFICATION_MAIL_WARNING);
  });

  it("lets no user change their own address: the e-mail change mail holds no link, and its link would expire after a second", () => {
    const r: Json = realm();
    expect(r["attributes"][UPDATE_EMAIL_LIFESPAN]).toBe("1");
    for (const key of ["emailUpdateConfirmationBody", "emailUpdateConfirmationBodyHtml"]) {
      expect(r["localizationTexts"]["en"][key]).toContain(EMAIL_CHANGE_WARNING);
      expect(r["localizationTexts"]["en"][key]).not.toContain("{0}");
    }
    expect(r["internationalizationEnabled"]).toBe(false);
  });

  it("refuses an @ in user names and keeps the address required and editable at sign-up", () => {
    const r: Json = realm();
    const config: Json = JSON.parse(r["components"]["org.keycloak.userprofile.UserProfileProvider"][0]["config"]["kc.user.profile.config"][0]);
    const pattern = new RegExp(config["attributes"].find((a: Json) => a["name"] === "username")["validations"]["pattern"]["pattern"]);
    expect(pattern.test("victim@example.com")).toBe(false);
    expect(pattern.test("google.112233445566778899")).toBe(true);
    expect(pattern.test("platform-admin")).toBe(true);
    expect(pattern.test("trader-2118509049")).toBe(true);
  });

  const cases: [string, (r: Json) => void, RegExp][] = [
    // T4: the person edits the provider's address on the review page.
    [
      "T4: a profile review before the account is created",
      (r) => flowOf(r, CHANCE_FIRST_BROKER_LOGIN_FLOW)["authenticationExecutions"].unshift({ authenticator: "idp-review-profile", authenticatorFlow: false, requirement: "REQUIRED", priority: 5 }),
      /the step idp-review-profile is not allowed \(the review page lets the person change the provider's address/,
    ],
    // T1: the mailed link proves the address and leaves a stranger's password on the account.
    [
      "T1: a mailed link as the proof",
      (r) => linkExisting(r)["authenticationExecutions"].splice(1, 0, { authenticator: "idp-email-verification", authenticatorFlow: false, requirement: "ALTERNATIVE", priority: 15 }),
      /the step idp-email-verification is not allowed \(the mailed link proves the address but leaves the existing account's password/,
    ],
    ["T1: a silent link", (r) => createOrLink(r)["authenticationExecutions"].push({ authenticator: "idp-auto-link", authenticatorFlow: false, requirement: "ALTERNATIVE", priority: 30 }), /the step idp-auto-link is not allowed/],
    ["T1: a link by detection only", (r) => (stepIn(linkExisting(r), "idp-username-password-form")["authenticator"] = "idp-detect-existing-broker-user"), /the step idp-detect-existing-broker-user is not allowed/],
    ["a step without its own rule", (r) => linkExisting(r)["authenticationExecutions"].push({ authenticator: "auth-cookie", authenticatorFlow: false, requirement: "ALTERNATIVE", priority: 40 }), /the step auth-cookie is not allowed \(only /],
    ["T1/T9: no password of the existing account", (r) => (linkExisting(r)["authenticationExecutions"] = linkExisting(r)["authenticationExecutions"].filter((e: Json) => e["authenticator"] !== "idp-username-password-form")), /linked only after idp-confirm-link and then idp-username-password-form/],
    ["T1/T9: the password optional", (r) => (stepIn(linkExisting(r), "idp-username-password-form")["requirement"] = "ALTERNATIVE"), /linked only after idp-confirm-link and then idp-username-password-form/],
    ["T1/T9: the password disabled", (r) => (stepIn(linkExisting(r), "idp-username-password-form")["requirement"] = "DISABLED"), /linked only after idp-confirm-link and then idp-username-password-form/],
    ["the password before the confirmation", (r) => (stepIn(linkExisting(r), "idp-username-password-form")["priority"] = 5), /linked only after idp-confirm-link and then idp-username-password-form/],
    ["no confirmation", (r) => (stepIn(linkExisting(r), "idp-confirm-link")["requirement"] = "DISABLED"), /linked only after idp-confirm-link/],
    ["the link subflow only conditional", (r) => (createOrLink(r)["authenticationExecutions"][1]["requirement"] = "CONDITIONAL"), /linked only after idp-confirm-link/],
    ["no new accounts through the provider", (r) => (stepIn(createOrLink(r), "idp-create-user-if-unique")["requirement"] = "REQUIRED"), /idp-create-user-if-unique must be there once, ALTERNATIVE/],
    ["a subflow not in the file", (r) => (createOrLink(r)["authenticationExecutions"][1]["flowAlias"] = "Handle Existing Account"), /the subflow "Handle Existing Account" must be defined in the file once/],
    ["the flow not in the file", (r) => (r["authenticationFlows"] = r["authenticationFlows"].filter((f: Json) => f["alias"] !== CHANCE_FIRST_BROKER_LOGIN_FLOW)), /first-login flow "chance first broker login": must be defined in the file as a top-level basic flow/],
    // T5: the address changes in the account console without a confirmation mail.
    ["T5: UPDATE_EMAIL off", (r) => (action(r, "UPDATE_EMAIL")["enabled"] = false), /^required action UPDATE_EMAIL: must be listed once, enabled, with the provider UPDATE_EMAIL \(an address changes only after a confirmation mail/],
    ["T5: UPDATE_EMAIL left out", (r) => (r["requiredActions"] = r["requiredActions"].filter((a: Json) => a["alias"] !== "UPDATE_EMAIL")), /^required action UPDATE_EMAIL: must be listed once/],
    ["T5: no list (Keycloak's defaults, UPDATE_EMAIL off)", (r) => delete r["requiredActions"], /^requiredActions must be listed/],
    ["T5: UPDATE_EMAIL without verification", (r) => (action(r, "UPDATE_EMAIL")["config"] = { verifyEmail: "false" }), /^required action UPDATE_EMAIL: config\.verifyEmail must not be "false"$/],
    ["VERIFY_EMAIL off", (r) => (action(r, "VERIFY_EMAIL")["enabled"] = false), /^required action VERIFY_EMAIL: must be listed once, enabled/],
    ["UPDATE_PASSWORD with another provider", (r) => (action(r, "UPDATE_PASSWORD")["providerId"] = "delete_account"), /^required action UPDATE_PASSWORD: must be listed once, enabled, with the provider UPDATE_PASSWORD/],
    // T2/T3: the session that registered would choose the password before the mail link.
    ["T2/T3: UPDATE_PASSWORD before VERIFY_EMAIL", (r) => (action(r, "UPDATE_PASSWORD")["priority"] = 45), /^required action VERIFY_EMAIL must come before UPDATE_PASSWORD \(lower priority; has: 50 and 45\)/],
    ["Keycloak's 30-minute login pages", (r) => (r["accessCodeLifespanLogin"] = 1800), /^accessCodeLifespanLogin must be set, at most 900 seconds \(has: 1800\)$/],
    ["no limit on required action pages", (r) => delete r["accessCodeLifespanUserAction"], /^accessCodeLifespanUserAction must be set, at most 300 seconds \(has: none\)$/],
    ["mailed links valid for an hour", (r) => (r["actionTokenGeneratedByUserLifespan"] = 3600), /^actionTokenGeneratedByUserLifespan must be set, at most 300 seconds/],
    ["a lifespan as a string", (r) => (r["actionTokenGeneratedByUserLifespan"] = "300"), /^actionTokenGeneratedByUserLifespan must be set/],
    // T3: the mail must tell a person who did not sign up not to follow the link.
    ["T3: Keycloak's own verification mail", (r) => delete r["localizationTexts"], /^localizationTexts\.en\.emailVerificationBody must hold the link \{0\} and the sentence/],
    ["T3: the warning only in the plain part", (r) => (r["localizationTexts"]["en"]["emailVerificationBodyHtml"] = "<p><a href=\"{0}\">Verify</a></p>"), /^localizationTexts\.en\.emailVerificationBodyHtml must hold/],
    ["an apostrophe in the mail text", (r) => (r["localizationTexts"]["en"]["emailVerificationBody"] += " Don't."), /^localizationTexts\.en\.emailVerificationBody must hold .*no apostrophe/],
    // Keycloak's column for descriptions: a longer one stopped the realm import on 2026-11-12.
    ["a flow description over 255 characters", (r) => (flowOf(r, CHANCE_FIRST_BROKER_LOGIN_FLOW)["description"] = "x".repeat(256)), /^authentication flow chance first broker login: the description has 256 characters, at most 255/],
    ["a client description over 255 characters", (r) => (clientOf(r, "web")["description"] = "y".repeat(300)), /^client web: the description has 300 characters, at most 255/],
    // Review finding 2: the account's second factor after its password.
    ["no second-factor subflow", (r) => (linkExisting(r)["authenticationExecutions"] = linkExisting(r)["authenticationExecutions"].filter((e: Json) => e["authenticatorFlow"] !== true)), /a CONDITIONAL subflow with conditional-user-configured and auth-otp-form/],
    ["the second factor disabled", (r) => (linkExisting(r)["authenticationExecutions"].find((e: Json) => e["authenticatorFlow"] === true)["requirement"] = "DISABLED"), /a CONDITIONAL subflow with conditional-user-configured and auth-otp-form/],
    ["the one-time code optional", (r) => (stepIn(flowOf(r, "chance first broker login second factor"), "auth-otp-form")["requirement"] = "ALTERNATIVE"), /a CONDITIONAL subflow with conditional-user-configured and auth-otp-form/],
    // Review finding 1: no user changes their own address (the change link moves the asking account to the clicker's address).
    ["T5: the e-mail change link valid", (r) => delete r["attributes"][UPDATE_EMAIL_LIFESPAN], new RegExp(`^attributes\\.${UPDATE_EMAIL_LIFESPAN.replace(".", "\\.")} must be "1"`)],
    ["T5: the e-mail change link valid for 5 minutes", (r) => (r["attributes"][UPDATE_EMAIL_LIFESPAN] = "300"), /must be "1" \(one second/],
    ["T5: the link back in the e-mail change mail", (r) => (r["localizationTexts"]["en"]["emailUpdateConfirmationBody"] += " {0}"), /^localizationTexts\.en\.emailUpdateConfirmationBody must say .* and leave out the link \{0\}/],
    ["T5: Keycloak's e-mail change mail", (r) => delete r["localizationTexts"]["en"]["emailUpdateConfirmationBodyHtml"], /^localizationTexts\.en\.emailUpdateConfirmationBodyHtml must say/],
    // Review finding 6: per-type link lifetimes and other attributes.
    ["a per-type lifetime of the verification link", (r) => (r["attributes"]["actionTokenGeneratedByUserLifespan.verify-email"] = "86400"), /^realm attribute actionTokenGeneratedByUserLifespan\.verify-email: not allowed/],
    ["CreateDefaultClientScopes off", (r) => (r["attributes"]["CreateDefaultClientScopes"] = "false"), /^realm attribute CreateDefaultClientScopes must be "true"/],
    // Review finding 7: one language.
    ["internationalization on", (r) => (r["internationalizationEnabled"] = true), /^internationalizationEnabled must be false/],
    ["internationalization not pinned", (r) => delete r["internationalizationEnabled"], /^internationalizationEnabled must be false/],
    ["a second locale", (r) => (r["supportedLocales"] = ["en", "sl"]), /^supportedLocales and defaultLocale may only be "en"/],
    // Review finding 4: user names of Google users, and no "@" in a user name.
    ["T9: no user name mapper", (r) => (r["identityProviderMappers"] = []), /^identity provider "google": exactly one user name mapper/],
    ["T9: Google's own user name", (r) => (r["identityProviderMappers"][0]["config"]["template"] = "${ALIAS}.${CLAIM.preferred_username}"), /^identity provider mapper .*: not allowed \(the only mapper is oidc-username-idp-mapper/],
    ["T9: the mapper on the lookup name only", (r) => (r["identityProviderMappers"][0]["config"]["target"] = "BROKER_USERNAME"), /exactly one user name mapper/],
    ["T9: no user profile", (r) => delete r["components"], /^user profile: exactly one org\.keycloak\.userprofile\.UserProfileProvider component/],
    [
      "T9: a user name with @",
      (r) => {
        const component = r["components"]["org.keycloak.userprofile.UserProfileProvider"][0];
        const config = JSON.parse(component["config"]["kc.user.profile.config"][0]);
        delete config["attributes"][0]["validations"]["pattern"];
        component["config"]["kc.user.profile.config"][0] = JSON.stringify(config);
      },
      /^user profile: the user name needs Keycloak's validations and a pattern that refuses "@"/,
    ],
    [
      "sign-up without the address",
      (r) => {
        const component = r["components"]["org.keycloak.userprofile.UserProfileProvider"][0];
        const config = JSON.parse(component["config"]["kc.user.profile.config"][0]);
        config["attributes"][1]["permissions"]["edit"] = ["admin"];
        component["config"]["kc.user.profile.config"][0] = JSON.stringify(config);
      },
      /^user profile: email must be required and editable by the user/,
    ],
  ];

  it.each(cases)("fails on %s", (_name, change, expected) => {
    const problems = mutated(change);
    expect(problems.some((problem) => expected.test(problem)), problems.join("\n")).toBe(true);
  });

  it("builds the image with Keycloak's verified e-mail change (feature update-email)", () => {
    expect(read("Dockerfile")).toMatch(/^\s*KC_FEATURES=update-email( \\)?$/m);
    expect(read("Dockerfile")).not.toMatch(/KC_FEATURES_DISABLED/);
  });
});

describe("the first platform admin", () => {
  const admin = (r: Json): Json => r["users"].find((u: Json) => u["username"] === PLATFORM_ADMIN.username);

  it("comes with its address from the environment, verified, with a name, and only the password to change", () => {
    const user = admin(realm());
    expect(user["email"]).toBe("${PLATFORM_ADMIN_EMAIL}");
    expect(user["emailVerified"]).toBe(true);
    expect(user["firstName"]).toBe("Platform");
    expect(user["lastName"]).toBe("Admin");
    expect(user["requiredActions"]).toEqual(["UPDATE_PASSWORD"]);
  });

  const cases: [string, (r: Json) => void, RegExp][] = [
    ["no address", (r) => delete admin(r)["email"], /platform admin: the e-mail address must be the placeholder \$\{PLATFORM_ADMIN_EMAIL\}/],
    ["a literal address", (r) => (admin(r)["email"] = "admin@example.com"), /platform admin: the e-mail address must be the placeholder/],
    ["another setting as the address", (r) => (admin(r)["email"] = "${SMTP_FROM}"), /platform admin: the e-mail address must be the placeholder/],
    ["an unverified address", (r) => (admin(r)["emailVerified"] = false), /platform admin: emailVerified must be true/],
    ["emailVerified left out", (r) => delete admin(r)["emailVerified"], /platform admin: emailVerified must be true/],
    ["no first name", (r) => delete admin(r)["firstName"], /platform admin: firstName must be a fixed name/],
    ["an empty last name", (r) => (admin(r)["lastName"] = " "), /platform admin: lastName must be a fixed name/],
    ["a name from the environment", (r) => (admin(r)["lastName"] = "${PLATFORM_ADMIN_USERNAME}"), /platform admin: lastName must be a fixed name/],
    ["a profile update on top", (r) => admin(r)["requiredActions"].push("UPDATE_PROFILE"), /platform admin: the only required action is UPDATE_PASSWORD \(has: UPDATE_PASSWORD, UPDATE_PROFILE\)/],
    ["a mail check on top", (r) => admin(r)["requiredActions"].push("VERIFY_EMAIL"), /platform admin: the only required action is UPDATE_PASSWORD/],
    ["no platform admin under the user name setting", (r) => (admin(r)["username"] = "root"), /the platform admin \$\{PLATFORM_ADMIN_USERNAME\} is missing/],
  ];

  it.each(cases)("fails on %s", (_name, change, expected) => {
    const problems = mutated(change);
    expect(problems.some((problem) => expected.test(problem)), problems.join("\n")).toBe(true);
  });

  it("is a local value in compose.yaml and an empty key in the chart that the schema requires; the real address comes from the Secret, which wins over the ConfigMap", () => {
    expect(read("compose.yaml")).toMatch(/^\s+PLATFORM_ADMIN_EMAIL: platform-admin@chance\.localhost # hooks:allow local development only$/m);
    const schema = JSON.parse(read("helm/values.schema.json")) as Json;
    expect(schema["properties"]["env"]["required"]).toContain("PLATFORM_ADMIN_EMAIL");
    expect(schema["properties"]["env"]["propertyNames"]["not"]["enum"]).not.toContain("PLATFORM_ADMIN_EMAIL");
    expect(read("helm/values.yaml")).toMatch(/^ {2}PLATFORM_ADMIN_EMAIL: ""$/m);
    expect(read("helm/values-prod.yaml")).toMatch(/^ {2}PLATFORM_ADMIN_EMAIL: ""$/m);
    // Kubernetes gives a name that several envFrom sources hold the value of the last source: the Secret must come after the ConfigMap.
    const envFrom = read("helm/templates/deployment.yaml").match(/envFrom:\n((?:\s+.*\n)+?)\s+startupProbe:/)?.[1] ?? "";
    const sources = [...envFrom.matchAll(/^\s+- (configMapRef|secretRef):/gm)].map((match) => match[1]);
    expect(sources).toEqual(["configMapRef", "secretRef"]);
  });
});

describe("the image", () => {
  it("refuses to start without any of the realm's settings", () => {
    const entrypoint = read("docker-entrypoint.sh");
    for (const name of REALM_PLACEHOLDERS) expect(entrypoint).toMatch(new RegExp(`^\\s+${name}$`, "m"));
  });

  it("gets a local value for every secret from compose.yaml, and the chart refuses it in the ConfigMap", () => {
    const compose = read("compose.yaml");
    const schema = JSON.parse(read("helm/values.schema.json")) as Json;
    const forbidden: string[] = schema["properties"]["env"]["propertyNames"]["not"]["enum"];
    // The mail relay's login is a credential too (with some relays it is an access key id).
    for (const name of REALM_PLACEHOLDERS.filter((placeholder) => /SECRET|PASSWORD/.test(placeholder) || placeholder === "SMTP_USER")) {
      expect(compose, name).toMatch(new RegExp(`^\\s+${name}: \\S+ # hooks:allow local development only$`, "m"));
      expect(forbidden, name).toContain(name);
      expect(read("helm/values.yaml"), name).toContain(name);
    }
  });

  describe("refuses a mail server setting that would send mail in a way nobody chose", () => {
    // Every setting set; the checks pass and the script then fails to find Keycloak (exit 127), which proves it got past them.
    const complete = (): NodeJS.ProcessEnv => ({
      PATH: process.env["PATH"],
      ...Object.fromEntries(read("docker-entrypoint.sh").match(/^\s+[A-Z][A-Z0-9_]*$/gm)?.map((line) => [line.trim(), "x"]) ?? []),
      SMTP_PORT: "587",
      SMTP_FROM: "no-reply@chance.example",
      SMTP_SSL: "false",
      SMTP_STARTTLS: "true",
      SMTP_AUTH: "true",
      PLATFORM_ADMIN_EMAIL: "platform-admin@chance.example",
    });
    const run = (env: NodeJS.ProcessEnv) => spawnSync("bash", [fileURLToPath(new URL("../docker-entrypoint.sh", import.meta.url))], { env, encoding: "utf8" });

    it("passes with a relay over STARTTLS and with the local catcher without TLS or login", () => {
      expect(run(complete()).status).toBe(127);
      expect(run({ ...complete(), SMTP_PORT: "1025", SMTP_FROM: "no-reply@chance.localhost", SMTP_STARTTLS: "false", SMTP_AUTH: "false" }).status).toBe(127);
      expect(run({ ...complete(), SMTP_PORT: "65535" }).status).toBe(127);
    });

    const refused: [string, NodeJS.ProcessEnv, RegExp][] = [
      ["a missing host", { SMTP_HOST: "" }, /missing settings: SMTP_HOST/],
      ["a missing password", { SMTP_PASSWORD: undefined }, /missing settings: SMTP_PASSWORD/],
      ["a switch that is not true or false", { SMTP_STARTTLS: "yes" }, /SMTP_STARTTLS must be true or false/],
      ["a port that is not a number", { SMTP_PORT: "smtp" }, /SMTP_PORT must be a port number/],
      ["port 0", { SMTP_PORT: "0" }, /SMTP_PORT must be a port number/],
      ["a port above 65535", { SMTP_PORT: "65536" }, /SMTP_PORT must be a port number/],
      ["a sender that is a name, not an address", { SMTP_FROM: "Chance" }, /SMTP_FROM must be an e-mail address/],
      ["a sender without a domain", { SMTP_FROM: "no-reply@" }, /SMTP_FROM must be an e-mail address/],
      ["a sender with a display name", { SMTP_FROM: "Chance <no-reply@chance.example>" }, /SMTP_FROM must be an e-mail address/],
      ["a login without TLS", { SMTP_STARTTLS: "false" }, /SMTP_AUTH=true needs SMTP_SSL=true or SMTP_STARTTLS=true/],
      ["TLS and STARTTLS together", { SMTP_SSL: "true" }, /not both/],
      ["no platform admin address", { PLATFORM_ADMIN_EMAIL: "" }, /missing settings: PLATFORM_ADMIN_EMAIL/],
      ["a platform admin address that is a name", { PLATFORM_ADMIN_EMAIL: "Platform Admin" }, /PLATFORM_ADMIN_EMAIL must be an e-mail address/],
      ["a platform admin address without a domain", { PLATFORM_ADMIN_EMAIL: "platform-admin@" }, /PLATFORM_ADMIN_EMAIL must be an e-mail address/],
      ["a platform admin address with a display name", { PLATFORM_ADMIN_EMAIL: "Admin <platform-admin@chance.example>" }, /PLATFORM_ADMIN_EMAIL must be an e-mail address/],
      ["no Google client id", { GOOGLE_CLIENT_ID: "" }, /missing settings: GOOGLE_CLIENT_ID$/m],
      ["no Google client secret", { GOOGLE_CLIENT_SECRET: undefined }, /missing settings: GOOGLE_CLIENT_SECRET$/m],
      ["neither of the Google client's settings", { GOOGLE_CLIENT_ID: undefined, GOOGLE_CLIENT_SECRET: "" }, /missing settings: GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET$/m],
      // The chart leaves the public host empty until the pipeline fills it from PUBLIC_HOST: Keycloak must not start without it.
      ["no public host (KC_HOSTNAME empty)", { KC_HOSTNAME: "" }, /missing settings: KC_HOSTNAME$/m],
      ["no web address (CHANCE_WEB_URL empty)", { CHANCE_WEB_URL: "" }, /missing settings: CHANCE_WEB_URL$/m],
      ["neither the public host nor the web address", { KC_HOSTNAME: "", CHANCE_WEB_URL: "" }, /missing settings: KC_HOSTNAME CHANCE_WEB_URL$/m],
    ];
    it.each(refused)("refuses %s", (_name, change, message) => {
      const result = run({ ...complete(), ...change });
      expect(result.status).toBe(64);
      expect(result.stderr).toMatch(message);
    });
  });

  it("pins the Keycloak base image by digest and imports the realm on start", () => {
    const dockerfile = read("Dockerfile");
    const bases = [...dockerfile.matchAll(/^FROM (\S+)/gm)].map((match) => match[1] ?? "");
    expect(bases.length).toBeGreaterThan(0);
    for (const base of bases) expect(base).toMatch(/^quay\.io\/keycloak\/keycloak:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$/);
    expect(dockerfile).toContain("realm/chance-realm.json /opt/keycloak/data/import/");
    expect(dockerfile).toMatch(/CMD \["start", "--optimized", "--import-realm"\]/);
  });

  it("serves Prometheus metrics on the management port only: built into the image, annotated, admitted for monitoring, never in the Service", () => {
    const dockerfile = read("Dockerfile");
    // Both stages repeat the options, so the start with --optimized never differs from what was built.
    expect(dockerfile.match(/^\s+KC_METRICS_ENABLED=true/gm)).toHaveLength(2);
    expect(dockerfile.match(/^\s+KC_HTTP_METRICS_HISTOGRAMS_ENABLED=true/gm)).toHaveLength(2);
    expect(dockerfile).not.toMatch(/KC_HTTP_MANAGEMENT_PORT/); // the port stays 9000: the chart's annotation and probes name it

    const deployment = read("helm/templates/deployment.yaml");
    expect(deployment).toMatch(/prometheus\.io\/scrape: "true"/);
    expect(deployment).toMatch(/prometheus\.io\/port: "9000"/);
    expect(deployment).toMatch(/prometheus\.io\/path: \/metrics/);
    expect(deployment).toMatch(/- name: management\n\s+containerPort: 9000/);

    // Only the HTTP port is a port of the Service: the management port is reached at the Pod address, by the kubelet and Prometheus.
    const ports = read("helm/templates/service.yaml").split(/^ {2}ports:\n/m)[1] ?? "";
    expect([...ports.matchAll(/^\s+- name: (\S+)/gm)].map((match) => match[1])).toEqual(["http"]);
    expect(read("helm/values.yaml")).not.toMatch(/managementPort/);

    const policy = read("helm/templates/networkpolicy.yaml");
    expect(policy).toMatch(/kubernetes\.io\/metadata\.name: \{\{ \.Values\.networkPolicy\.metrics\.namespace \| quote \}\}\n\s+ports:\n\s+- port: management/);
    expect(read("helm/values.yaml")).toMatch(/metrics:\n\s+namespace: monitoring/);
    // The management rule admits the monitoring namespace alone, no Pod selector (a bare podSelector: {} is every Pod of the namespace).
    const managementRule = policy.split(/^ {4}- from:\n/m).find((rule) => /- port: management/.test(rule)) ?? "";
    expect(managementRule).toMatch(/namespaceSelector:/);
    expect(managementRule).not.toMatch(/podSelector/);
  });
});
