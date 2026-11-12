import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { DockerComposeEnvironment, Wait } from "testcontainers";
import type { StartedDockerComposeEnvironment } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Builds the image, starts it with its database and the mail catcher from compose.yaml and checks the contract the
// services rely on.
// The values below are the local development values of compose.yaml.
const ROOT = new URL("../../", import.meta.url).pathname;
const BASE = "http://localhost:8081";
const MANAGEMENT = "http://localhost:9001";
const ADMIN = `${BASE}/admin/realms/chance`;
// The local mail catcher of compose.yaml (Mailpit's web UI and API).
const MAILPIT = "http://localhost:8025";
const LOCAL = {
  tenantsSecret: "tenants-local-secret",
  paymentsSecret: "payments-local-secret",
  marketMakerSecret: "market-maker-local-secret",
  marketsSecret: "markets-local-secret",
  tenantsMarketsSecret: "tenants-markets-local-secret",
  admin: "admin",
  adminPassword: "admin-local-only",
  googleClientId: "chance-local-placeholder.apps.googleusercontent.com",
  googleClientSecret: "google-local-placeholder-not-a-secret",
}; // hooks:allow local development values

type Json = Record<string, any>;

let environment: StartedDockerComposeEnvironment | undefined;

async function tokenFor(realm: string, form: Record<string, string>): Promise<string> {
  const response = await fetch(`${BASE}/realms/${realm}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form),
  });
  const body = (await response.json()) as Json;
  if (!response.ok) throw new Error(`token request failed: ${response.status} ${JSON.stringify(body)}`);
  return body["access_token"] as string;
}

const tenantsToken = () =>
  tokenFor("chance", { grant_type: "client_credentials", client_id: "tenants", client_secret: LOCAL.tenantsSecret });
const paymentsToken = () =>
  tokenFor("chance", { grant_type: "client_credentials", client_id: "payments", client_secret: LOCAL.paymentsSecret });
const masterToken = () =>
  tokenFor("master", { grant_type: "password", client_id: "admin-cli", username: LOCAL.admin, password: LOCAL.adminPassword });

async function api(token: string, method: string, path: string, body?: unknown) {
  const response = await fetch(path.startsWith("http") ? path : `${ADMIN}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  return { status: response.status, location: response.headers.get("location"), json: text ? (JSON.parse(text) as unknown) : null };
}

const claims = (jwt: string): Json => JSON.parse(Buffer.from(jwt.split(".")[1] ?? "", "base64url").toString("utf8")) as Json;

async function createUser(admin: string, name: string): Promise<string> {
  const created = await api(admin, "POST", "/users", {
    username: name,
    email: `${name}@example.com`,
    firstName: "Test",
    lastName: "User",
    enabled: true,
    emailVerified: true,
    credentials: [{ type: "password", value: "Integration-test-1", temporary: false }],
  });
  expect(created.status).toBe(201);
  return created.location?.split("/").pop() ?? "";
}

beforeAll(async () => {
  environment = await new DockerComposeEnvironment(ROOT, "compose.yaml")
    .withBuild()
    .withWaitStrategy("keycloak-1", Wait.forHttp("/health/ready", 9000).forStatusCode(200).withStartupTimeout(300_000))
    .up();
});

afterAll(async () => {
  await environment?.down({ removeVolumes: true });
});

describe("the imported realm", () => {
  it("publishes the issuer and keys the services expect", async () => {
    const discovery = (await (await fetch(`${BASE}/realms/chance/.well-known/openid-configuration`)).json()) as Json;
    expect(discovery["issuer"]).toBe(`${BASE}/realms/chance`);
    const keys = (await (await fetch(discovery["jwks_uri"] as string)).json()) as Json;
    expect(keys["keys"].some((key: Json) => key["use"] === "sig" && key["kty"] === "RSA")).toBe(true);
  });

  it("serves health only on the management port", async () => {
    expect((await fetch(`${MANAGEMENT}/health/ready`)).status).toBe(200);
    expect((await fetch(`${BASE}/health/ready`)).status).toBe(404);
  });

  it("serves Prometheus metrics only on the management port (REQ-20)", async () => {
    const response = await fetch(`${MANAGEMENT}/metrics`);
    expect(response.status).toBe(200);
    expect(await response.text()).toMatch(/^# HELP /m);
    expect((await fetch(`${BASE}/metrics`)).status).toBe(404);
  });

  it("resolves the placeholders, also inside longer values", async () => {
    const admin = await masterToken();
    const [web] = (await api(admin, "GET", "/clients?clientId=web")).json as Json[];
    expect(web?.["redirectUris"]).toEqual(["http://localhost:5173/*"]);
    expect(web?.["attributes"]["pkce.code.challenge.method"]).toBe("S256");
    expect(web?.["publicClient"]).toBe(true);
  });

  it("creates the first platform admin with a temporary password, its verified address and a name", async () => {
    const admin = await masterToken();
    const [user] = (await api(admin, "GET", "/users?username=platform-admin&exact=true")).json as Json[];
    expect(user).toBeDefined();
    // Only the password change is left for the first login: the address (compose.yaml) is imported as verified.
    expect(user?.["requiredActions"]).toEqual(["UPDATE_PASSWORD"]);
    expect(user).toMatchObject({ email: "platform-admin@chance.localhost", emailVerified: true, firstName: "Platform", lastName: "Admin" });
    const roles = (await api(admin, "GET", `/users/${user?.["id"]}/role-mappings/realm`)).json as Json[];
    expect(roles.map((role) => role["name"])).toContain("platform-admin");
  });

  it("binds the realm's own registration flow, whose password step sets the password only after the mail link", async () => {
    const admin = await masterToken();
    const realm = (await api(admin, "GET", "")).json as Json;
    expect(realm["registrationFlow"]).toBe("chance registration");
    const steps = (await api(admin, "GET", `/authentication/flows/${encodeURIComponent("chance registration")}/executions`)).json as Json[];
    const password = steps.find((step) => step["providerId"] === "registration-password-action");
    expect(password?.["requirement"]).toBe("REQUIRED");
    expect(password?.["authenticationConfig"]).toBeUndefined();
  });

  it("links a provider login to an existing account only after its password, and changes an address only after a mail", async () => {
    const admin = await masterToken();
    const realm = (await api(admin, "GET", "")).json as Json;
    expect(realm["firstBrokerLoginFlow"]).toBe("chance first broker login");
    const steps = (await api(admin, "GET", `/authentication/flows/${encodeURIComponent("chance first broker login")}/executions`)).json as Json[];
    const requirement = Object.fromEntries(steps.filter((step) => step["providerId"]).map((step) => [step["providerId"], step["requirement"]]));
    expect(requirement).toMatchObject({ "idp-create-user-if-unique": "ALTERNATIVE", "idp-confirm-link": "REQUIRED", "idp-username-password-form": "REQUIRED" });
    expect(Object.keys(requirement)).not.toEqual(expect.arrayContaining(["idp-review-profile"]));
    expect(Object.keys(requirement)).not.toEqual(expect.arrayContaining(["idp-email-verification"]));
    const actions = (await api(admin, "GET", "/authentication/required-actions")).json as Json[];
    const byAlias = Object.fromEntries(actions.map((action) => [action["alias"], action]));
    expect(byAlias["UPDATE_EMAIL"]?.["enabled"]).toBe(true);
    expect(byAlias["VERIFY_EMAIL"]?.["priority"]).toBeLessThan(byAlias["UPDATE_PASSWORD"]?.["priority"]);
    expect(realm["accessCodeLifespanLogin"]).toBeLessThanOrEqual(900);
  });

  it("verifies e-mail addresses through the mail server of compose.yaml", async () => {
    const admin = await masterToken();
    const realm = (await api(admin, "GET", "")).json as Json;
    expect(realm["verifyEmail"]).toBe(true);
    expect(realm["smtpServer"]).toMatchObject({
      host: "mailpit",
      port: "1025",
      from: "no-reply@chance.localhost",
      fromDisplayName: "Chance",
      ssl: "false",
      starttls: "false",
      auth: "false",
    });
  });

  it("offers Google login with the client of compose.yaml through the realm's own first-login flow, and password reset", async () => {
    const admin = await masterToken();
    const realm = (await api(admin, "GET", "")).json as Json;
    expect(realm["resetPasswordAllowed"]).toBe(true);
    const google = (await api(admin, "GET", "/identity-provider/instances/google")).json as Json;
    expect(google).toMatchObject({ alias: "google", providerId: "google", enabled: true, trustEmail: true, firstBrokerLoginFlowAlias: "chance first broker login" });
    expect(google["hideOnLogin"]).not.toBe(true);
    expect(google["config"]).toMatchObject({ clientId: LOCAL.googleClientId, defaultScope: "openid email profile", syncMode: "IMPORT" });
    // The Admin REST API masks the client secret (StripSecretsUtils); it only shows that one is set.
    expect(google["config"]["clientSecret"]).toBeTruthy();
    expect(google["config"]["clientSecret"]).not.toBe(LOCAL.googleClientSecret);
    // A Google login with the address of an existing account links only after the user confirms and signs in with its password.
    const steps = (await api(admin, "GET", `/authentication/flows/${encodeURIComponent("chance first broker login")}/executions`)).json as Json[];
    const ids = steps.map((step) => step["providerId"]);
    expect(ids).toEqual(expect.arrayContaining(["idp-create-user-if-unique", "idp-confirm-link", "idp-username-password-form"]));
    for (const forbidden of ["idp-auto-link", "idp-email-verification", "idp-review-profile"]) expect(ids).not.toContain(forbidden);
    // Google users are named google.<sub>; the e-mail change link lasts one second (no user changes their own address).
    const mappers = (await api(admin, "GET", "/identity-provider/instances/google/mappers")).json as Json[];
    expect(mappers.map((mapper) => [mapper["identityProviderMapper"], mapper["config"]?.["template"]])).toEqual([["oidc-username-idp-mapper", "google.${CLAIM.sub}"]]);
    expect(realm["attributes"]?.["actionTokenGeneratedByUserLifespan.update-email"]).toBe("1");
    expect(realm["internationalizationEnabled"]).toBe(false);
  });

  it("sends the verification mail to a new address, which the local mail catcher receives", async () => {
    const admin = await masterToken();
    const name = `signup-${randomUUID().slice(0, 8)}`;
    const created = await api(admin, "POST", "/users", { username: name, email: `${name}@example.com`, enabled: true, emailVerified: false });
    expect(created.status).toBe(201);
    const userId = created.location?.split("/").pop() ?? "";
    expect((await api(admin, "PUT", `/users/${userId}/send-verify-email`)).status).toBe(204);
    // Keycloak hands the mail over before it answers; the short wait covers Mailpit storing it.
    let recipients: string[] = [];
    for (let attempt = 0; attempt < 10 && !recipients.includes(`${name}@example.com`); attempt += 1) {
      const inbox = (await (await fetch(`${MAILPIT}/api/v1/messages`)).json()) as Json;
      recipients = (inbox["messages"] as Json[]).flatMap((message) => (message["To"] as Json[]).map((to) => to["Address"] as string));
      if (!recipients.includes(`${name}@example.com`)) await new Promise((resolve) => setTimeout(resolve, 500));
    }
    expect(recipients).toContain(`${name}@example.com`);
  });
});

describe("the tenants service account", () => {
  it("can do exactly what the tenants service does", async () => {
    const tenants = await tenantsToken();
    const admin = await masterToken();
    const tenantId = randomUUID();
    const userId = await createUser(admin, `member-${tenantId.slice(0, 8)}`);

    // Create the organization (alias = tenant id) and find it again by an exact search.
    const created = await api(tenants, "POST", "/organizations", { name: tenantId, alias: tenantId, description: "Acme", enabled: true });
    expect(created.status).toBe(201);
    const found = (await api(tenants, "GET", `/organizations?search=${tenantId}&exact=true`)).json as Json[];
    const organizationId = found[0]?.["id"] as string;
    expect(found).toHaveLength(1);

    // Add the member (a repeat answers 409).
    expect((await api(tenants, "POST", `/organizations/${organizationId}/members`, userId)).status).toBe(201);
    expect((await api(tenants, "POST", `/organizations/${organizationId}/members`, userId)).status).toBe(409);

    // Give it a realm role the way the setRole of the tenants adapter does: the wanted role is added first, then the other
    // one is taken away (a DELETE with the role in the body; a repeat, or a user that never held it, also answers 204).
    const mappings = `/users/${userId}/role-mappings/realm`;
    const wanted = (await api(tenants, "GET", "/roles/tenant-admin")).json as Json;
    const other = (await api(tenants, "GET", "/roles/trader")).json as Json;
    const held = async () => ((await api(tenants, "GET", mappings)).json as Json[]).map((mapping) => mapping["name"]);
    expect((await api(tenants, "POST", mappings, [other])).status).toBe(204); // the role it held before
    expect(await held()).toContain("trader");
    expect((await api(tenants, "POST", mappings, [wanted])).status).toBe(204);
    expect((await api(tenants, "DELETE", mappings, [other])).status).toBe(204);
    expect(await held()).toContain("tenant-admin");
    expect(await held()).not.toContain("trader");
    expect((await api(tenants, "DELETE", mappings, [other])).status).toBe(204);

    // Remove the member again. The reconciler only adds members, so this is not part of the service flow: it shows that
    // the account may take a member out of an organization, and leaves the organization as it was.
    expect((await api(tenants, "DELETE", `/organizations/${organizationId}/members/${userId}`)).status).toBe(204);
  });

  it("cannot change the realm itself or reach another realm", async () => {
    const tenants = await tenantsToken();
    expect((await api(tenants, "POST", "/roles", { name: `extra-${randomUUID()}` })).status).toBe(403);
    expect((await api(tenants, "POST", "/clients", { clientId: `extra-${randomUUID()}` })).status).toBe(403);
    expect([401, 403]).toContain((await api(tenants, "GET", `${BASE}/admin/realms/master/users`)).status);
  });
});

describe("the payments service account", () => {
  it("gets a token by client credentials that carries the audience chance and no admin right", async () => {
    const token = claims(await paymentsToken());
    expect(token["iss"]).toBe(`${BASE}/realms/chance`);
    expect(token["azp"]).toBe("payments");
    expect([token["aud"]].flat()).toContain("chance");
    // No role of ours, no realm-management role and no admin scope: trading can tell it from a user and from tenants.
    const roles = (token["realm_access"]?.["roles"] ?? []) as string[];
    for (const role of ["platform-admin", "tenant-admin", "trader"]) expect(roles).not.toContain(role);
    expect(Object.keys(token["resource_access"] ?? {})).not.toContain("realm-management");
    expect(String(token["scope"]).split(" ")).not.toContain("kc-admin-api");
    expect(token["organization"]).toBeUndefined();
  });

  it("is refused by the Admin REST API, for reading and for writing", async () => {
    const payments = await paymentsToken();
    expect([401, 403]).toContain((await api(payments, "GET", "/organizations")).status);
    expect([401, 403]).toContain((await api(payments, "GET", "/users")).status);
    expect([401, 403]).toContain((await api(payments, "GET", "/roles/trader")).status);
    expect([401, 403]).toContain((await api(payments, "POST", "/roles", { name: `extra-${randomUUID()}` })).status);
    expect([401, 403]).toContain((await api(payments, "GET", `${BASE}/admin/realms/master/users`)).status);
  });

  it("gets no token with a wrong secret, and none by a password", async () => {
    const wrong = await fetch(`${BASE}/realms/chance/protocol/openid-connect/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: "payments", client_secret: "not-the-secret" }),
    });
    expect(wrong.status).toBe(401);
    const password = await fetch(`${BASE}/realms/chance/protocol/openid-connect/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "password",
        client_id: "payments",
        client_secret: LOCAL.paymentsSecret,
        username: "platform-admin",
        password: "anything",
      }),
    });
    expect(password.ok).toBe(false);
  });
});

describe("the market-maker, markets and tenants-markets service accounts", () => {
  it.each([
    ["market-maker", LOCAL.marketMakerSecret],
    ["markets", LOCAL.marketsSecret],
    ["tenants-markets", LOCAL.tenantsMarketsSecret],
  ])("%s gets a token by client credentials with the audience chance, no role of ours and no admin right", async (clientId, secret) => {
    const raw = await tokenFor("chance", { grant_type: "client_credentials", client_id: clientId, client_secret: secret });
    const token = claims(raw);
    expect(token["azp"]).toBe(clientId);
    expect([token["aud"]].flat()).toContain("chance");
    const roles = (token["realm_access"]?.["roles"] ?? []) as string[];
    for (const role of ["platform-admin", "tenant-admin", "trader"]) expect(roles).not.toContain(role);
    expect(Object.keys(token["resource_access"] ?? {})).not.toContain("realm-management");
    expect(token["organization"]).toBeUndefined();
    expect([401, 403]).toContain((await api(raw, "GET", "/organizations")).status);
  });
});

describe("a member's access token", () => {
  it("carries the tenant, the role and the audience chance", async () => {
    const admin = await masterToken();
    const tenants = await tenantsToken();
    const tenantId = randomUUID();
    const username = `trader-${tenantId.slice(0, 8)}`;
    const userId = await createUser(admin, username);
    await api(tenants, "POST", "/organizations", { name: tenantId, alias: tenantId, enabled: true });
    const organizationId = ((await api(tenants, "GET", `/organizations?search=${tenantId}&exact=true`)).json as Json[])[0]?.["id"];
    await api(tenants, "POST", `/organizations/${organizationId}/members`, userId);
    // The tenant role is a group of the organization (token contract v2), not a realm role: a realm role would reach every
    // organization of the user. A second organization, where the user is an admin, must stay out of the first token.
    const addToGroup = async (alias: string, organization: string, group: string): Promise<void> => {
      const created = await api(tenants, "POST", `/organizations/${organization}/groups`, { name: group });
      expect(created.status, alias).toBe(201);
      const groupId = created.location?.split("/").pop() ?? "";
      expect((await api(tenants, "PUT", `/organizations/${organization}/groups/${groupId}/members/${userId}`)).status, alias).toBe(204);
    };
    await addToGroup(tenantId, organizationId as string, "trader");
    const otherTenant = randomUUID();
    await api(tenants, "POST", "/organizations", { name: otherTenant, alias: otherTenant, enabled: true });
    const otherId = ((await api(tenants, "GET", `/organizations?search=${otherTenant}&exact=true`)).json as Json[])[0]?.["id"] as string;
    await api(tenants, "POST", `/organizations/${otherId}/members`, userId);
    await addToGroup(otherTenant, otherId, "tenant-admin");

    // A test-only client with password logins and the web client's scopes and audience mapper, because the web
    // client itself only allows the browser login.
    const realm = JSON.parse(readFileSync(new URL("../../realm/chance-realm.json", import.meta.url), "utf8")) as Json;
    const web = (realm["clients"] as Json[]).find((client) => client["clientId"] === "web") ?? {};
    const clientId = `it-${tenantId.slice(0, 8)}`;
    const client = await api(admin, "POST", "/clients", {
      clientId,
      publicClient: true,
      standardFlowEnabled: false,
      directAccessGrantsEnabled: true,
      defaultClientScopes: web["defaultClientScopes"],
      protocolMappers: web["protocolMappers"],
    });
    expect(client.status).toBe(201);

    const tokenFrom = async (alias: string) =>
      claims(
        await tokenFor("chance", {
          grant_type: "password",
          client_id: clientId,
          username,
          password: "Integration-test-1",
          scope: `openid chance-organization:${alias}`,
        }),
      );
    const token = await tokenFrom(tenantId);
    expect(token["iss"]).toBe(`${BASE}/realms/chance`);
    expect(token["sub"]).toBe(userId);
    expect([token["aud"]].flat()).toContain("chance");
    // Exactly the requested organization, with the member's group there, and no tenant role among the realm roles.
    expect(Object.keys(token["organization"] as Json)).toEqual([tenantId]);
    expect((token["organization"] as Json)[tenantId]["groups"]).toEqual(["/trader"]);
    const realmRoles = (token["realm_access"]?.["roles"] ?? []) as string[];
    for (const role of ["trader", "tenant-admin", "platform-admin"]) expect(realmRoles).not.toContain(role);
    // The same user asks for its other organization and is an admin there.
    const other = await tokenFrom(otherTenant);
    expect(Object.keys(other["organization"] as Json)).toEqual([otherTenant]);
    expect((other["organization"] as Json)[otherTenant]["groups"]).toEqual(["/tenant-admin"]);
  });
});
