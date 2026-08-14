import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { AdminClient } from "../AdminClient";
import type { UsersResponse } from "../types";

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("AdminClient.getUsers", () => {
  const originalFetch = globalThis.fetch;
  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("requests /api/admin/users with page/limit params and strict typing", async () => {
    const backend: { success: boolean; message: string; data: UsersResponse } = {
      success: true,
      message: "List of users",
      data: {
        total: 2,
        users: [
          { id: "u1", email: "a@example.com", emailVerified: true, mfaEnabled: false, createdAt: "2026-01-01T00:00:00Z" },
          { id: "u2", email: "b@example.com", emailVerified: false, mfaEnabled: true, createdAt: "2026-01-02T00:00:00Z" },
        ],
      },
    };
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(jsonResponse(backend));

    const client = new AdminClient({ serverUrl: "http://localhost:8080/", adminToken: "admin-tok" });
    const res = await client.getUsers(2, 25);

    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/admin/users?page=2&limit=25");
    expect(init.method).toBe("GET");
    expect((init.headers as Headers).get("Authorization")).toBe("Bearer admin-tok");

    expect(res.success).toBe(true);
    expect(res.data.total).toBe(2);
    expect(res.data.users[0].email).toBe("a@example.com");

    // compile-time: paginated response shape is strictly enforced
    const total: number = res.data.total;
    const emails: string[] = res.data.users.map((u) => u.email);
    expect(total).toBe(2);
    expect(emails).toHaveLength(2);
  });

  it("defaults to page=1&limit=10", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      jsonResponse({ success: true, message: "ok", data: { total: 0, users: [] } }),
    );
    const client = new AdminClient({ serverUrl: "http://localhost:8080", adminToken: "t" });
    await client.getUsers();
    const [url] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/admin/users?page=1&limit=10");
  });

  it("throws with the server error message on failure", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response(JSON.stringify({ success: false, error: { message: "Unauthorized" } }), { status: 401 }),
    );
    const client = new AdminClient({ serverUrl: "http://localhost:8080", adminToken: "bad" });
    await expect(client.getUsers()).rejects.toThrow("Unauthorized");
  });
});
