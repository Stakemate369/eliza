/**
 * API-key auth boundary coverage keeps storage outages distinct from invalid
 * credentials so clients retry instead of prompting users to rotate good keys:
 * a validateApiKey THROW (datastore down) must map to 503 on BOTH guards, while
 * a null return (genuinely invalid key) stays a 401.
 */

import { beforeEach, describe, expect, mock, test } from "bun:test";

let validateBehavior: () => Promise<unknown> = async () => {
  throw new Error("database unavailable");
};
const validateApiKey = mock(() => validateBehavior());

mock.module("../services/api-keys", () => ({
  apiKeysService: {
    validateApiKey,
    incrementUsageDebounced: mock(async () => undefined),
  },
}));

mock.module("../services/users", () => ({
  usersService: {
    getWithOrganization: mock(async () => null),
  },
}));

mock.module("./steward-client", () => ({
  verifyStewardTokenCached: mock(async () => null),
}));

mock.module("./playwright-test-session", () => ({
  PLAYWRIGHT_TEST_SESSION_COOKIE_NAME: "pw-test-session",
  verifyPlaywrightTestSessionToken: mock(() => null),
}));

mock.module("../utils/logger", () => ({
  logger: {
    error: mock(() => undefined),
    warn: mock(() => undefined),
  },
}));

const { requireApiKeyCredential, requireUserOrApiKey, requireUserOrApiKeyWithOrg } = await import(
  "./workers-hono-auth"
);

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
  validateApiKey.mockClear();
  validateBehavior = async () => {
    throw new Error("database unavailable");
  };
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
});
