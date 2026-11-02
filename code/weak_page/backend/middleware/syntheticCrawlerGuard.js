export function syntheticCrawlerGuard(req, res, next) {
  const isSyntheticProbe =
    req.get("x-weak-page-crawler") === "synthetic-probe";
  const isXssValidationProbe =
    req.get("x-weak-page-xss-validation") === "stored-contact";
  const isInvalidLoginProbe =
    req.method === "POST" && req.path === "/auth/login";
  if (isXssValidationProbe) {
    const contactPost =
      req.method === "POST" &&
      req.path === "/contact" &&
      /^weakpage-xss-probe-[a-f0-9]{12}<img\b/i.test(
        String(req.body?.message || "")
      );
    const contactCleanup =
      req.method === "DELETE" &&
      /^\/contact\/\d+$/.test(req.path) &&
      /^weakpage-xss-probe-[a-f0-9]{12}$/.test(
        String(req.body?.marker || "")
      );
    const contactRead =
      req.method === "GET" &&
      /^\/contact\/xss-inbox\/\d+$/.test(req.path) &&
      /^weakpage-xss-probe-[a-f0-9]{12}$/.test(
        String(req.query?.marker || "")
      );
    if (
      process.env.NODE_ENV !== "production" &&
      (contactPost || contactCleanup || contactRead)
    ) {
      return next();
    }
    return res.status(422).json({
      message: "Invalid or disabled weak_page XSS validation write."
    });
  }
  if (
    isSyntheticProbe &&
    !isInvalidLoginProbe &&
    !["GET", "HEAD", "OPTIONS"].includes(req.method)
  ) {
    return res.status(422).json({
      message: "Synthetic weakPageCrawler write probe rejected."
    });
  }
  return next();
}
