export function syntheticCrawlerGuard(req, res, next) {
  const isSyntheticProbe =
    req.get("x-weak-page-crawler") === "synthetic-probe";
  const isInvalidLoginProbe =
    req.method === "POST" && req.path === "/auth/login";
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
