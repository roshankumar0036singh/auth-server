import { ApiResponse, UsersResponse } from './types';

export interface AdminClientConfig {
  serverUrl: string;
  adminToken: string;
}

/**
 * A dedicated client for performing administrative actions.
 * Requires an admin access token.
 */
export class AdminClient {
  private readonly serverUrl: string;
  private readonly adminToken: string;

  constructor(config: AdminClientConfig) {
    this.serverUrl = config.serverUrl.replace(/\/$/, "");
    this.adminToken = config.adminToken;
  }


  private async fetchApi<T>(path: string, options: RequestInit = {}): Promise<ApiResponse<T>> {
    const headers = new Headers(options.headers || {});
    headers.set("Content-Type", "application/json");
    headers.set("Authorization", `Bearer ${this.adminToken}`);

    const response = await fetch(`${this.serverUrl}${path}`, {
      ...options,
      headers,
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error?.message || "An error occurred");
    }
    return data;
  }

  /**
   * List all users (strictly typed against the backend's PaginatedUsers).
   * Resolved Issue #61: returns `{ total, users }` with optional
   * page/limit query parameters (backend clamps limit to 1..100).
   *
   * @param page  1-based page number (default 1)
   * @param limit Items per page, 1-100 (default 10)
   */
  public async getUsers(page: number = 1, limit: number = 10): Promise<ApiResponse<UsersResponse>> {
    const query = new URLSearchParams({ page: String(page), limit: String(limit) });
    return this.fetchApi<UsersResponse>(`/api/admin/users?${query.toString()}`, { method: "GET" });
  }

  /**
   * Lock a user account.
   * @param userId The ID of the user to lock.
   */
  public async lockUser(userId: string): Promise<ApiResponse<{ userID: string }>> {
    return this.fetchApi<{ userID: string }>(`/api/admin/users/${userId}/lock`, { method: "POST" });
  }

  /**
   * Unlock a user account.
   * @param userId The ID of the user to unlock.
   */
  public async unlockUser(userId: string): Promise<ApiResponse<{ userID: string }>> {
    return this.fetchApi<{ userID: string }>(`/api/admin/users/${userId}/unlock`, { method: "POST" });
  }

  /**
   * Delete a user account permanently.
   * @param userId The ID of the user to delete.
   */
  public async deleteUser(userId: string): Promise<ApiResponse<null>> {
    return this.fetchApi<null>(`/api/admin/users/${userId}`, { method: "DELETE" });
  }
}
