/** A short, readable device description from a User-Agent. Best effort; unknown stays unknown. */
export function describeDevice(userAgent: string | null | undefined): { os: string; browser: string; label: string } {
  const ua = userAgent ?? "";
  const os = /Windows/i.test(ua) ? "Windows"
    : /iPhone|iPad|iPod/i.test(ua) ? "iOS"
    : /Android/i.test(ua) ? "Android"
    : /Mac OS X|Macintosh/i.test(ua) ? "Mac OS X"
    : /Linux|X11/i.test(ua) ? "Linux"
    : "알 수 없는 기기";
  const browser = /Edg\//.test(ua) ? "Edge"
    : /OPR\/|Opera/.test(ua) ? "Opera"
    : /Firefox\//.test(ua) ? "Firefox"
    : /Chrome\//.test(ua) ? "Chrome"
    : /Safari\//.test(ua) ? "Safari"
    : "";
  return { os, browser, label: browser ? `${os} ${browser}` : os };
}
