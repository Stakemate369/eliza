/**
 * API-key auth boundary coverage keeps storage outages distinct from invalid
 * credentials so clients retry instead of prompting users to rotate good keys:
 * a validateApiKey THROW (datastore down) must map to 503 on BOTH guards, while
 * a null return (genuinely invalid key) stays a 401.
 */

import { afterEach, beforeEach, describe, expect, mock, spyOn, test } from "bun:test";

let validateBehavior: () => Promise<unknown> = async () => {
  throw new Error("database unavailable");
};
const { apiKeysService } = await import("../services/api-keys");
const { usersService } = await import("../services/users");
let validateApiKey: ReturnType<typeof spyOn>;
let incrementUsageDebounced: ReturnType<typeof spyOn>;
let getWithOrganization: ReturnType<typeof spyOn>;

mock.module("./steward-client", () => ({
  verifyStewardTokenCached: mock(async () => null),
}));

mock.module("./playwright-test-session", () => ({
  PLAYWRIGHT_TEST_SESSION_COOKIE_NAME: "pw-test-session",
  verifyPlaywrightTestSessionToken: mock(() => null),
}));

mock.module("../utils/logger", () => ({
  logger: {
    debug: mock(() => undefined),
    error: mock(() => undefined),
    info: mock(() => undefined),
    warn: mock(() => undefined),
  },
}));

const {
  getCurrentUser,
  requireApiKeyCredential,
  requireSessionUserWithOrg,
  requireUserOrApiKey,
  requireUserOrApiKeyWithOrg,
} = await import("./workers-hono-auth");

function contextWithHeaders(headers: Record<string, string>) {
  const state = new Map<string, unknown>();
  return {
    env: {},
    executionCtx: { waitUntil: mock(() => undefined) },
    req: {
      url: "https://api.example.test/v1/models",
      header: (name: string) => headers[name.toLowerCase()] ?? null,
    },
    get: (key: string) => state.get(key),
    set: (key: string, value: unknown) => state.set(key, value),
  };
}

function contextWithApiKey(apiKey: string) {
  return contextWithHeaders({ "x-api-key": apiKey });
}

beforeEach(() => {
  validateBehavior = async () => {
    throw new Error("database unavailable");
  };
  validateApiKey = spyOn(apiKeysService, "validateApiKey").mockImplementation(
    () => validateBehavior() as never,
  );
  incrementUsageDebounced = spyOn(apiKeysService, "incrementUsageDebounced").mockResolvedValue(
    undefined,
  );
  getWithOrganization = spyOn(usersService, "getWithOrganization").mockResolvedValue(null);
});

afterEach(() => {
  validateApiKey.mockRestore();
  incrementUsageDebounced.mockRestore();
  getWithOrganization.mockRestore();
});

describe("Workers API-key auth", () => {
  test("returns a service-unavailable error when API-key storage throws", async () => {
    await expect(
      requireUserOrApiKey(contextWithApiKey("eliza_live_key") as never),
    ).rejects.toMatchObject({
      status: 503,
      code: "service_unavailable",
      message: "API key validation is temporarily unavailable. Please retry.",
    });
  });

  test("requireUserOrApiKeyWithOrg maps the same storage throw to 503", async () => {
    await expect(
      requireUserOrApiKeyWithOrg(contextWithApiKey("eliza_live_key") as never),
    ).rejects.toMatchObject({
      status: 503,
      code: "service_unavailable",
    });
  });

  test("a null validation result stays 401 invalid-key on requireUserOrApiKey", async () => {
    validateBehavior = async () => null;
    await expect(
      requireUserOrApiKey(contextWithApiKey("eliza_bad_key") as never),
    ).rejects.toMatchObject({
      status: 401,
      code: "authentication_required",
    });
  });

  test("a null validation result stays 401 invalid-key on requireUserOrApiKeyWithOrg", async () => {
    validateBehavior = async () => null;
    await expect(
      requireUserOrApiKeyWithOrg(contextWithApiKey("eliza_bad_key") as never),
    ).rejects.toMatchObject({
      status: 401,
      code: "authentication_required",
    });
  });

  test("the exact-credential guard rejects missing and JWT session auth", async () => {
    await expect(requireApiKeyCredential(contextWithHeaders({}) as never)).rejects.toMatchObject({
      status: 401,
      code: "authentication_required",
    });
    await expect(
      requireApiKeyCredential(
        contextWithHeaders({ authorization: "Bearer header.payload.signature" }) as never,
      ),
    ).rejects.toMatchObject({ status: 401, code: "authentication_required" });
    expect(validateApiKey).not.toHaveBeenCalled();
  });

  test("the exact-credential guard rejects ambiguous API-key headers", async () => {
    await expect(
      requireApiKeyCredential(
        contextWithHeaders({
          authorization: "Bearer eliza_bearer_key",
          "x-api-key": "eliza_header_key",
        }) as never,
      ),
    ).rejects.toMatchObject({ status: 401, code: "authentication_required" });
    expect(validateApiKey).not.toHaveBeenCalled();
  });

  test("the exact-credential guard records the ID proven by the presented key", async () => {
    const validated = {
      id: "11111111-1111-4111-8111-111111111111",
      key_hash: "a".repeat(64),
      is_active: true,
      expires_at: new Date(Date.now() + 60_000),
    };
    validateBehavior = async () => validated;
    const context = contextWithHeaders({ authorization: "Bearer eliza_exact_key" });

    expect(await requireApiKeyCredential(context as never)).toBe(validated);
    expect(context.get("authMethod")).toBe("api_key");
    expect(context.get("apiKeyId")).toBe(validated.id);
    expect(validateApiKey).toHaveBeenCalledWith("eliza_exact_key");
  });

  test("the exact-credential guard distinguishes an invalid key from storage outage", async () => {
    validateBehavior = async () => null;
    await expect(
      requireApiKeyCredential(contextWithApiKey("eliza_invalid") as never),
    ).rejects.toMatchObject({ status: 401, code: "authentication_required" });

    validateBehavior = async () => {
      throw new Error("database unavailable");
    };
    await expect(
      requireApiKeyCredential(contextWithApiKey("eliza_valid_shape") as never),
    ).rejects.toMatchObject({ status: 503, code: "service_unavailable" });
  });

  test("API-key org auth resolves the key owner, records context, and tracks usage", async () => {
    const validated = {
      id: "11111111-1111-4111-8111-111111111111",
      user_id: "22222222-2222-4222-8222-222222222222",
      key_hash: "a".repeat(64),
      is_active: true,
      expires_at: new Date(Date.now() + 60_000),
    };
    const user = {
      id: validated.user_id,
      email: "mobile-owner@example.test",
      email_verified: true,
      organization_id: "33333333-3333-4333-8333-333333333333",
      organization: {
        id: "33333333-3333-4333-8333-333333333333",
        name: "Mobile Org",
        is_active: true,
      },
      is_active: true,
      role: "member",
      steward_user_id: "steward-user",
      wallet_address: null,
      is_anonymous: false,
    };
    validateBehavior = async () => validated;
    getWithOrganization.mockResolvedValue(user);
    const context = contextWithApiKey("eliza_live_key");

    await expect(requireUserOrApiKeyWithOrg(context as never)).resolves.toMatchObject({
      id: user.id,
      organization_id: user.organization_id,
    });
    expect(context.get("authMethod")).toBe("api_key");
    expect(context.get("apiKeyId")).toBe(validated.id);
    expect(context.executionCtx.waitUntil).toHaveBeenCalled();
  });

  test("API-key org auth rejects missing, inactive, and organizationless owners", async () => {
    const validated = {
      id: "11111111-1111-4111-8111-111111111111",
      user_id: "22222222-2222-4222-8222-222222222222",
      key_hash: "a".repeat(64),
      is_active: true,
      expires_at: new Date(Date.now() + 60_000),
    };
    validateBehavior = async () => validated;

    getWithOrganization.mockResolvedValueOnce(null);
    await expect(
      requireUserOrApiKeyWithOrg(contextWithApiKey("eliza_live_key") as never),
    ).rejects.toMatchObject({ status: 401 });

    getWithOrganization.mockResolvedValueOnce({
      id: validated.user_id,
      is_active: false,
      organization: { id: "33333333-3333-4333-8333-333333333333", is_active: true },
    });
    await expect(
      requireUserOrApiKeyWithOrg(contextWithApiKey("eliza_live_key") as never),
    ).rejects.toMatchObject({ status: 403 });

    getWithOrganization.mockResolvedValueOnce({
      id: validated.user_id,
      is_active: true,
      organization_id: null,
      organization: null,
    });
    await expect(
      requireUserOrApiKeyWithOrg(contextWithApiKey("eliza_live_key") as never),
    ).rejects.toMatchObject({ status: 403 });
  });

  test("session-only API-key management rejects API keys and accepts cached sessions", async () => {
    await expect(
      requireSessionUserWithOrg(contextWithApiKey("eliza_live_key") as never),
    ).rejects.toMatchObject({
      status: 401,
      code: "session_auth_required",
    });

    const context = contextWithHeaders({});
    context.set("user", {
      id: "22222222-2222-4222-8222-222222222222",
      organization_id: "33333333-3333-4333-8333-333333333333",
      organization: {
        id: "33333333-3333-4333-8333-333333333333",
        name: "Session Org",
        is_active: true,
      },
      is_active: true,
    });
    context.set("authMethod", "session");
    await expect(requireSessionUserWithOrg(context as never)).resolves.toMatchObject({
      organization_id: "33333333-3333-4333-8333-333333333333",
    });
  });

  test("getCurrentUser caches null when no Steward token is present", async () => {
    const context = contextWithHeaders({});
    await expect(getCurrentUser(context as never)).resolves.toBeNull();
    await expect(getCurrentUser(context as never)).resolves.toBeNull();
    expect(context.get("user")).toBeNull();
  });
});
