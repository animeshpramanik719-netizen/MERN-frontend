// Centralized configuration for API and media URLs
// Production backend hosted on Render: https://photo-gallery-1-d5n0.onrender.com

export const BACKEND_URL =
  import.meta.env.VITE_BACKEND_URL || "https://photo-gallery-1-d5n0.onrender.com";

export const resolveImageUrl = (url) => {
  if (!url) return "";
  if (
    url.startsWith("http://") ||
    url.startsWith("https://") ||
    url.startsWith("data:") ||
    url.startsWith("blob:")
  ) {
    return url;
  }
  return `${BACKEND_URL}${url.startsWith("/") ? "" : "/"}${url}`;
};
