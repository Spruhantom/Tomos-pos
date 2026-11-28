export type ApiOptions = { tenantId?: string; method?: "GET" | "POST" | "PUT" | "DELETE"; body?: unknown };

export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message); this.name = "ApiError"; }
}

export async function api<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const headers = new Headers({ Accept: "application/json" });
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (options.tenantId) headers.set("X-Tenant-ID", options.tenantId);
  const response = await fetch(path.startsWith("/") ? path : "/api/v1/" + path, {
    method: options.method ?? "GET", headers, credentials: "same-origin", cache: "no-store",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (response.status === 204) return undefined as T;
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = typeof payload === "object" && payload !== null && "error" in payload && typeof payload.error === "string" ? payload.error : "Request failed (" + response.status + ")";
    throw new ApiError(detail, response.status);
  }
  return payload as T;
}
