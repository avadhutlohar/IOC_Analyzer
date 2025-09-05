// frontend/src/config.js
// Normalize API base (remove trailing slashes) and provide a helper to build paths
export const API_BASE = (import.meta.env.VITE_API_BASE || "http://localhost:8000").replace(/\/+$/, "");
export function apiUrl(path) {
  return `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;
}