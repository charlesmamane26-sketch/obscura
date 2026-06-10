use std::collections::HashMap;
use std::sync::RwLock;
use url::Url;

const DEFAULT_SAME_SITE: &str = "Lax";

pub struct CookieJar {
    cookies: RwLock<HashMap<String, HashMap<String, CookieEntry>>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CookieEntry {
    name: String,
    value: String,
    path: String,
    domain: String,
    secure: bool,
    http_only: bool,
    expires: Option<u64>,
    same_site: String,
}

impl CookieJar {
    pub fn new() -> Self {
        CookieJar {
            cookies: RwLock::new(HashMap::new()),
        }
    }

    pub fn set_cookie(&self, set_cookie_str: &str, url: &Url) {
        let parts: Vec<&str> = set_cookie_str.splitn(2, ';').collect();
        let name_value = parts[0].trim();
        let (name, value) = match name_value.split_once('=') {
            Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
            None => return,
        };

        let mut domain = url.host_str().unwrap_or("").to_lowercase();
        let mut domain_explicit = false;
        let mut path = url.path().to_string();
        let mut secure = false;
        let mut http_only = false;
        let mut expires: Option<u64> = None;
        let mut same_site = "Lax".to_string();

        if parts.len() > 1 {
            for attr in parts[1].split(';') {
                let attr = attr.trim();
                if let Some((key, val)) = attr.split_once('=') {
                    match key.trim().to_lowercase().as_str() {
                        "domain" => {
                            domain = val.trim().trim_start_matches('.').to_lowercase();
                            domain_explicit = true;
                        }
                        "path" => {
                            path = val.trim().to_string();
                        }
                        "expires" => {
                            if let Ok(ts) = parse_http_date(val.trim()) {
                                expires = Some(ts);
                            }
                        }
                        "max-age" => {
                            if let Ok(secs) = val.trim().parse::<i64>() {
                                if secs <= 0 {
                                    expires = Some(0);
                                } else {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    expires = Some(now + secs as u64);
                                }
                            }
                        }
                        "samesite" => {
                            same_site = val.trim().to_string();
                        }
                        _ => {}
                    }
                } else {
                    match attr.to_lowercase().as_str() {
                        "secure" => secure = true,
                        "httponly" => http_only = true,
                        _ => {}
                    }
                }
            }
        }

        // COOK-01: an explicit Domain= must be one the request host is actually
        // under, and must not be a public suffix — otherwise a hostile response
        // could scope a cookie to an unrelated parent/sibling/TLD (cross-site
        // cookie injection / session fixation).
        if domain_explicit && !is_cookie_domain_allowed(url.host_str().unwrap_or(""), &domain) {
            tracing::debug!("Rejected cross-scope cookie '{}' for Domain={}", name, domain);
            return;
        }

        // COOK-PREFIX-MISSING: enforce __Host-/__Secure- name-prefix integrity.
        if !cookie_prefix_ok(&name, secure, url.scheme() == "https", !domain_explicit, &path) {
            tracing::debug!("Rejected prefixed cookie '{}' (failed __Host-/__Secure- rules)", name);
            return;
        }

        if let Some(exp) = expires {
            if exp == 0 {
                let mut cookies = self.cookies.write().unwrap();
                if let Some(domain_cookies) = cookies.get_mut(&domain) {
                    domain_cookies.remove(&name);
                }
                return;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if exp < now {
                return;
            }
        }

        let entry = CookieEntry {
            name: name.clone(),
            value,
            path,
            domain: domain.clone(),
            secure,
            http_only,
            expires,
            same_site,
        };

        let mut cookies = self.cookies.write().unwrap();
        cookies.entry(domain).or_default().insert(name, entry);
    }

    /// Build the `Cookie` header for `url`, treating the request as same-site
    /// (sends every host/path/secure-matching cookie regardless of `SameSite`).
    /// This is the behaviour every caller had before COOK-04; cross-site
    /// enforcement is available via [`get_cookie_header_ctx`](Self::get_cookie_header_ctx)
    /// once the navigation stack threads the initiating site.
    pub fn get_cookie_header(&self, url: &Url) -> String {
        self.get_cookie_header_ctx(url, SameSiteContext::SameSite)
    }

    /// Build the `Cookie` header for `url`, enforcing each cookie's `SameSite`
    /// attribute against the request's same-site context (COOK-04). Pass
    /// [`SameSiteContext::CrossSiteTopLevel`] / [`SameSiteContext::CrossSite`]
    /// from the navigation/redirect path (with the initiating top-level site) to
    /// withhold `Strict`/`Lax` cookies on cross-site requests and restore CSRF
    /// protection; [`SameSiteContext::SameSite`] keeps the legacy "send all".
    pub fn get_cookie_header_ctx(&self, url: &Url, ctx: SameSiteContext) -> String {
        let host = url.host_str().unwrap_or("");
        let path = url.path();
        let is_secure = url.scheme() == "https";
        let cookies = self.cookies.read().unwrap();

        let mut matching: Vec<String> = Vec::new();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (domain, domain_cookies) in cookies.iter() {
            if !domain_matches(host, domain) {
                continue;
            }
            for entry in domain_cookies.values() {
                if let Some(exp) = entry.expires {
                    if exp < now {
                        continue;
                    }
                }
                if entry.secure && !is_secure {
                    continue;
                }
                if !path_matches(path, &entry.path) {
                    continue;
                }
                // COOK-04: drop Strict on any cross-site request and Lax on
                // cross-site subresource / unsafe-method requests.
                if !same_site_allows(&entry.same_site, ctx) {
                    continue;
                }
                matching.push(format!("{}={}", entry.name, entry.value));
            }
        }

        matching.join("; ")
    }

    pub fn get_all_cookies(&self) -> Vec<CookieInfo> {
        let cookies = self.cookies.read().unwrap();
        let mut result = Vec::new();
        for domain_cookies in cookies.values() {
            for entry in domain_cookies.values() {
                result.push(CookieInfo {
                    name: entry.name.clone(),
                    value: entry.value.clone(),
                    domain: entry.domain.clone(),
                    path: entry.path.clone(),
                    secure: entry.secure,
                    http_only: entry.http_only,
                    same_site: entry.same_site.clone(),
                    expires: entry.expires.map(|e| e as i64),
                });
            }
        }
        result
    }

    pub fn set_cookies_from_cdp(&self, cookies: Vec<CookieInfo>) {
        let mut jar = self.cookies.write().unwrap();
        for cookie in cookies {
            // COOK-CDP-INJECT-1 / COOK-03: the programmatic ingestion path (CDP
            // Network.setCookie / Storage.setCookies / MCP browser_set_cookie) is
            // reachable by an unauthenticated A2 client and previously stored the
            // domain verbatim — letting `Domain=com` become a supercookie. Reject
            // public-suffix and bare-TLD domains here just like the Set-Cookie /
            // document.cookie paths do via is_cookie_domain_allowed.
            if cookie.domain.trim_start_matches('.').is_empty() || is_public_suffix(&cookie.domain) {
                tracing::debug!(
                    "Rejected CDP/MCP cookie '{}' for public-suffix/empty Domain={}",
                    cookie.name,
                    cookie.domain
                );
                continue;
            }
            // COOK-PREFIX-MISSING: a __Host-/__Secure- cookie injected via CDP/MCP
            // must satisfy the prefix integrity rules too. Transport is not modeled
            // here, so the cookie's own Secure flag governs; host-only is best-effort
            // (a leading-dot domain is explicitly subdomain-spanning).
            let host_only = !cookie.domain.starts_with('.');
            if !cookie_prefix_ok(&cookie.name, cookie.secure, true, host_only, &cookie.path) {
                tracing::debug!(
                    "Rejected CDP/MCP prefixed cookie '{}' (failed __Host-/__Secure- rules)",
                    cookie.name
                );
                continue;
            }
            let same_site = if cookie.same_site.is_empty() {
                DEFAULT_SAME_SITE.to_string()
            } else {
                cookie.same_site
            };
            let expires = cookie.expires.and_then(|e| if e > 0 { Some(e as u64) } else { None });
            let entry = CookieEntry {
                name: cookie.name.clone(),
                value: cookie.value,
                path: cookie.path,
                domain: cookie.domain.clone(),
                secure: cookie.secure,
                http_only: cookie.http_only,
                expires,
                same_site,
            };
            jar.entry(cookie.domain).or_default().insert(cookie.name, entry);
        }
    }

    pub fn get_js_visible_cookies(&self, url: &Url) -> String {
        let host = url.host_str().unwrap_or("");
        let path = url.path();
        let is_secure = url.scheme() == "https";
        let cookies = self.cookies.read().unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut matching: Vec<String> = Vec::new();

        for (domain, domain_cookies) in cookies.iter() {
            if !domain_matches(host, domain) {
                continue;
            }
            for entry in domain_cookies.values() {
                if entry.http_only {
                    continue;
                }
                if let Some(exp) = entry.expires {
                    if exp < now {
                        continue;
                    }
                }
                if entry.secure && !is_secure {
                    continue;
                }
                if !path_matches(path, &entry.path) {
                    continue;
                }
                matching.push(format!("{}={}", entry.name, entry.value));
            }
        }

        matching.join("; ")
    }

    pub fn set_cookie_from_js(&self, cookie_str: &str, url: &Url) {
        let parts: Vec<&str> = cookie_str.splitn(2, ';').collect();
        let name_value = parts[0].trim();
        let (name, value) = match name_value.split_once('=') {
            Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
            None => return,
        };

        let mut domain = url.host_str().unwrap_or("").to_lowercase();
        let mut domain_explicit = false;
        let mut path = url.path().to_string();
        let mut secure = false;
        let mut expires: Option<u64> = None;
        let mut same_site = "Lax".to_string();

        if parts.len() > 1 {
            for attr in parts[1].split(';') {
                let attr = attr.trim();
                if let Some((key, val)) = attr.split_once('=') {
                    match key.trim().to_lowercase().as_str() {
                        "domain" => {
                            domain = val.trim().trim_start_matches('.').to_lowercase();
                            domain_explicit = true;
                        }
                        "path" => {
                            path = val.trim().to_string();
                        }
                        "expires" => {
                            if let Ok(ts) = parse_http_date(val.trim()) {
                                expires = Some(ts);
                            }
                        }
                        "max-age" => {
                            if let Ok(secs) = val.trim().parse::<i64>() {
                                if secs <= 0 {
                                    expires = Some(0);
                                } else {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    expires = Some(now + secs as u64);
                                }
                            }
                        }
                        "samesite" => {
                            same_site = val.trim().to_string();
                        }
                        _ => {}
                    }
                } else {
                    match attr.to_lowercase().as_str() {
                        "secure" => secure = true,
                        _ => {}
                    }
                }
            }
        }

        // COOK-01: page JS (document.cookie) must not scope a cookie to an
        // unrelated parent/sibling/TLD. Reject an explicit Domain= the document
        // host is not under, or that is a public suffix.
        if domain_explicit && !is_cookie_domain_allowed(url.host_str().unwrap_or(""), &domain) {
            tracing::debug!("Rejected cross-scope JS cookie '{}' for Domain={}", name, domain);
            return;
        }

        // COOK-PREFIX-MISSING: page JS must not forge a __Host-/__Secure- cookie.
        if !cookie_prefix_ok(&name, secure, url.scheme() == "https", !domain_explicit, &path) {
            tracing::debug!("Rejected prefixed JS cookie '{}' (failed __Host-/__Secure- rules)", name);
            return;
        }

        if let Some(exp) = expires {
            if exp == 0 {
                let mut cookies = self.cookies.write().unwrap();
                if let Some(domain_cookies) = cookies.get_mut(&domain) {
                    domain_cookies.remove(&name);
                }
                return;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if exp < now {
                return;
            }
        }

        let entry = CookieEntry {
            name: name.clone(),
            value,
            path,
            domain: domain.clone(),
            secure,
            http_only: false,
            expires,
            same_site,
        };

        let mut cookies = self.cookies.write().unwrap();
        cookies.entry(domain).or_default().insert(name, entry);
    }

    pub fn delete_cookie(&self, name: &str, domain: &str) {
        let mut cookies = self.cookies.write().unwrap();
        if domain.is_empty() {
            for domain_cookies in cookies.values_mut() {
                domain_cookies.remove(name);
            }
        } else {
            let domains_to_try = [
                domain.to_string(),
                format!(".{}", domain.trim_start_matches('.')),
                domain.trim_start_matches('.').to_string(),
            ];
            for d in &domains_to_try {
                if let Some(domain_cookies) = cookies.get_mut(d.as_str()) {
                    domain_cookies.remove(name);
                }
            }
        }
    }

    pub fn delete_cookies_filtered(&self, name: &str, domain: &str, path: Option<&str>) {
        let mut cookies = self.cookies.write().unwrap();
        let matches_path = |entry_path: &str| match path {
            Some(p) => entry_path == p,
            None => true,
        };
        if domain.is_empty() {
            for domain_cookies in cookies.values_mut() {
                domain_cookies.retain(|n, e| !(n == name && matches_path(&e.path)));
            }
        } else {
            let domains_to_try = [
                domain.to_string(),
                format!(".{}", domain.trim_start_matches('.')),
                domain.trim_start_matches('.').to_string(),
            ];
            for d in &domains_to_try {
                if let Some(domain_cookies) = cookies.get_mut(d.as_str()) {
                    domain_cookies.retain(|n, e| !(n == name && matches_path(&e.path)));
                }
            }
        }
    }

    pub fn clear(&self) {
        self.cookies.write().unwrap().clear();
    }

    /// Serialize all non-expired cookies to a JSON file.
    /// Writes atomically via tempfile then rename.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), std::io::Error> {
        use std::io::Write;

        let cookies = self.cookies.read().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut all: Vec<CookieInfo> = Vec::new();
        for domain_cookies in cookies.values() {
            for entry in domain_cookies.values() {
                if let Some(exp) = entry.expires {
                    if exp < now {
                        continue;
                    }
                }
                all.push(CookieInfo {
                    name: entry.name.clone(),
                    value: entry.value.clone(),
                    domain: entry.domain.clone(),
                    path: entry.path.clone(),
                    secure: entry.secure,
                    http_only: entry.http_only,
                    same_site: entry.same_site.clone(),
                    expires: entry.expires.map(|e| e as i64),
                });
            }
        }

        let json = serde_json::to_string_pretty(&all).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut tmp = tempfile::NamedTempFile::new_in(
            path.parent().unwrap_or(std::path::Path::new(".")),
        )?;
        tmp.write_all(json.as_bytes())?;
        // COOK-06: the jar stores session credentials (including HttpOnly/Secure
        // values) in cleartext, so restrict the file to the owner. Best-effort
        // on Windows, which relies on the user-profile ACL instead of mode bits.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600));
        }
        tmp.persist(path).map_err(|e| e.error)?;
        // COOK-06-WINDOWS-PERMS: Windows has no mode bits, so the unix branch
        // above is a no-op there and the persisted jar inherits the parent
        // directory ACL — exposing cleartext session cookies to other local users
        // when --storage-dir is outside the user profile. Best-effort: drop
        // inherited ACEs and grant only the current user, via icacls.
        #[cfg(windows)]
        {
            if let Ok(user) = std::env::var("USERNAME") {
                if !user.is_empty() {
                    let _ = std::process::Command::new("icacls")
                        .arg(path)
                        .arg("/inheritance:r")
                        .arg("/grant:r")
                        .arg(format!("{}:F", user))
                        .output();
                }
            }
        }
        Ok(())
    }

    /// Load cookies from a JSON file into the jar.
    /// Merges with existing cookies (does not clear).
    /// Returns the number of cookies loaded.
    pub fn load_from_file(&self, path: &std::path::Path) -> Result<usize, std::io::Error> {
        if !path.exists() {
            return Ok(0);
        }
        let data = std::fs::read_to_string(path)?;
        let cookies: Vec<CookieInfo> =
            serde_json::from_str(&data).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
            })?;
        let count = cookies.len();
        self.set_cookies_from_cdp(cookies);
        Ok(count)
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CookieInfo {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    #[serde(rename = "httpOnly")]
    pub http_only: bool,
    #[serde(default, rename = "sameSite")]
    pub same_site: String,
    #[serde(default)]
    pub expires: Option<i64>,
}

fn parse_http_date(s: &str) -> Result<u64, ()> {
    let months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];

    let s = s.replace('-', " ");
    let parts: Vec<&str> = s.split_whitespace().collect();

    if parts.len() < 5 { return Err(()); }

    let day: u64 = parts[1].parse().map_err(|_| ())?;
    let month = months.iter().position(|m| parts[2].to_lowercase().starts_with(m))
        .ok_or(())? as u64 + 1;
    let year: u64 = parts[3].parse().map_err(|_| ())?;

    let time_parts: Vec<&str> = parts[4].split(':').collect();
    let hour: u64 = time_parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minute: u64 = time_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let second: u64 = time_parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    let mut days_total: u64 = 0;
    for y in 1970..year {
        days_total += if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
    }
    let days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    for m in 1..month {
        days_total += days_in_month[m as usize] + if m == 2 && is_leap { 1 } else { 0 };
    }
    days_total += day - 1;

    Ok(days_total * 86400 + hour * 3600 + minute * 60 + second)
}

/// RFC 6265 domain-match for cookie *storage* validation: true if `host` is
/// exactly `domain` or a dot-boundary subdomain of it.
fn host_is_under_domain(host: &str, domain: &str) -> bool {
    if host.eq_ignore_ascii_case(domain) {
        return true;
    }
    if host.len() <= domain.len() {
        return false;
    }
    let prefix = host.len() - domain.len();
    host.is_char_boundary(prefix)
        && host.as_bytes()[prefix - 1] == b'.'
        && host[prefix..].eq_ignore_ascii_case(domain)
}

/// Best-effort public-suffix test. A `Domain=` equal to a public suffix would
/// scope the cookie to EVERY site under it. A full PSL (the `publicsuffix`
/// crate) is the complete answer; this built-in covers bare TLDs plus the most
/// common ICANN multi-label suffixes and the cloud-hosting *private* suffixes
/// that are routinely abused for cross-tenant cookie injection, without adding a
/// dependency (COOK-PSL-HARDCODED-GAPS — expanded coverage).
fn is_public_suffix(domain: &str) -> bool {
    let domain = domain.trim_start_matches('.');
    if !domain.contains('.') {
        return true; // bare TLD / single label: com, localhost, internal, …
    }
    const COMMON: &[&str] = &[
        // United Kingdom
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "sch.uk", "ltd.uk", "plc.uk",
        // Australia / New Zealand
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
        // Japan
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "gr.jp",
        // China / Hong Kong / Taiwan / Singapore / Malaysia / Philippines
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "com.hk", "com.tw", "com.sg", "com.my", "com.ph",
        // Americas
        "com.br", "net.br", "org.br", "gov.br",
        "com.mx", "com.ar", "com.co", "com.ve", "com.pe", "com.uy",
        // Europe / Middle East / Africa / India / Korea / others
        "com.tr", "com.ua", "com.ng", "com.pk", "com.eg",
        "co.in", "net.in", "org.in", "gov.in", "ac.in",
        "co.za", "co.kr", "or.kr", "ne.kr", "co.il", "co.id", "co.th", "co.ke", "co.ve",
        "eu.org",
        // Hosting / CDN PRIVATE suffixes (PSL "PRIVATE" section) — each tenant is
        // a distinct registrable site, so a Domain= scoped to the suffix itself
        // is a cross-tenant supercookie.
        "github.io", "gitlab.io", "herokuapp.com", "appspot.com", "web.app", "firebaseapp.com",
        "cloudfunctions.net", "pages.dev", "workers.dev", "r2.dev", "vercel.app", "netlify.app",
        "azurewebsites.net", "azurestaticapps.net", "cloudfront.net", "fastly.net",
        "amazonaws.com", "s3.amazonaws.com", "elasticbeanstalk.com", "sevalla.app",
        "ondigitalocean.app", "render.com", "fly.dev",
    ];
    COMMON.iter().any(|s| domain.eq_ignore_ascii_case(s))
}

/// Same-site context of an egress request, used to enforce a cookie's `SameSite`
/// attribute at send time (COOK-04). The jar stores `same_site` but the request
/// pipeline must tell it whether the request is same-site relative to the
/// initiating (top-level) document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameSiteContext {
    /// Same-site request (or initiator unknown): all cookies allowed. This is the
    /// default and preserves the pre-COOK-04 behaviour for callers that do not yet
    /// thread the initiator.
    SameSite,
    /// Cross-site **top-level navigation** with a safe method (GET/HEAD): `Lax`
    /// and `None` cookies are sent, `Strict` is withheld.
    CrossSiteTopLevel,
    /// Cross-site subresource load or unsafe-method request: only `None` is sent.
    CrossSite,
}

/// COOK-04 egress decision: may a cookie with stored `same_site` be attached to a
/// request in `ctx`? `Lax` is the default when the attribute is absent/unknown.
fn same_site_allows(same_site: &str, ctx: SameSiteContext) -> bool {
    let ss = same_site.trim();
    let is_strict = ss.eq_ignore_ascii_case("Strict");
    let is_none = ss.eq_ignore_ascii_case("None");
    match ctx {
        SameSiteContext::SameSite => true,
        SameSiteContext::CrossSiteTopLevel => !is_strict, // Lax + None
        SameSiteContext::CrossSite => is_none,            // None only
    }
}

/// Registrable domain (eTLD+1) of a host, used for the same-site comparison.
/// `www.example.com` and `api.example.com` -> `example.com`; for a host directly
/// under a multi-label / private public suffix (`a.azurewebsites.net`) the host
/// itself is the registrable domain, so two tenants are correctly *not* same-site.
fn registrable_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return host; // IP literal (or empty): the literal is its own site
    }
    let labels: Vec<&str> = host.split('.').collect();
    for i in 0..labels.len() {
        if is_public_suffix(&labels[i..].join(".")) {
            // eTLD+1 = the public suffix plus one more label to its left.
            return labels[i.saturating_sub(1)..].join(".");
        }
    }
    host
}

/// True if two URLs are "same-site" — same registrable domain (eTLD+1) — for
/// SameSite cookie enforcement (COOK-04). Scheme/port are irrelevant to
/// same-site (unlike same-origin). A missing host on either side is not
/// same-site (fail-safe).
pub fn is_same_site(a: &Url, b: &Url) -> bool {
    match (a.host_str(), b.host_str()) {
        (Some(ha), Some(hb)) => registrable_domain(ha) == registrable_domain(hb),
        _ => false,
    }
}

/// RFC 6265 §5.1.4 path-match. The previous `request_path.starts_with(cookie_path)`
/// leaked a cookie scoped to `Path=/admin` onto `/administrator` / `/admin-x`
/// (COOK-PATH-BOUND-1). A match requires an exact equality, a cookie-path that
/// ends in `/`, or a `/` at the request-path char immediately after the prefix.
fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

/// RFC 6265bis cookie name-prefix rules (COOK-PREFIX-MISSING). A real browser
/// rejects a `__Secure-`/`__Host-` cookie that does not meet the prefix's
/// integrity requirements; obscura must too, or a network/MITM response (A1) or
/// an unauthenticated CDP/MCP client (A2) could forge or overwrite a cookie the
/// site pinned with a prefix (session fixation). Prefixes are matched
/// case-insensitively.
/// - `__Secure-`: the cookie must be `Secure` and set over a secure transport.
/// - `__Host-`: the above, plus host-only (no explicit `Domain=`) and `Path=/`.
fn cookie_prefix_ok(name: &str, secure: bool, secure_transport: bool, host_only: bool, path: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("__host-") {
        return secure && secure_transport && host_only && path == "/";
    }
    if lower.starts_with("__secure-") {
        return secure && secure_transport;
    }
    true
}

/// Validate an explicit `Domain=` attribute against the request host (audit
/// COOK-01): a page must not be able to scope a cookie to an unrelated parent,
/// sibling, or TLD — that is cross-site cookie injection / session fixation.
/// Only applied when a `Domain=` attribute is explicitly present; host-only
/// cookies (no `Domain=`) are always stored under the exact host.
fn is_cookie_domain_allowed(host: &str, domain: &str) -> bool {
    let host = host.trim_start_matches('.');
    if host.is_empty() || domain.is_empty() {
        return false;
    }
    host_is_under_domain(host, domain) && !is_public_suffix(domain)
}

fn domain_matches(host: &str, domain: &str) -> bool {
    // Avoid allocations on the hot path. Cookie lookup runs per fetch
    // (every subresource on a page) and walks every domain in the jar.
    // Previously this allocated 2 lowercase Strings + a "." prefix
    // per (host, domain) pair.
    let domain = domain.trim_start_matches('.');
    if host.len() < domain.len() {
        return false;
    }
    // Exact match (case-insensitive)
    if host.eq_ignore_ascii_case(domain) {
        return true;
    }
    // Suffix match with a '.' boundary: host = "sub.example.com",
    // domain = "example.com". The byte before the suffix in host
    // must be '.'.
    let prefix_len = host.len() - domain.len();
    if prefix_len < 1 { return false; }
    if !host.is_char_boundary(prefix_len) { return false; }
    if host.as_bytes()[prefix_len - 1] != b'.' { return false; }
    host[prefix_len..].eq_ignore_ascii_case(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get_cookie() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/path").unwrap();
        jar.set_cookie("session=abc123; Path=/; Secure; HttpOnly", &url);

        let header = jar.get_cookie_header(&url);
        assert!(header.contains("session=abc123"));
    }

    #[test]
    fn test_cookie_domain_matching() {
        let jar = CookieJar::new();
        let url = Url::parse("https://www.example.com/").unwrap();
        jar.set_cookie("token=xyz; Domain=example.com", &url);

        let header = jar.get_cookie_header(&url);
        assert!(header.contains("token=xyz"));

        let sub_url = Url::parse("https://api.example.com/").unwrap();
        let header2 = jar.get_cookie_header(&sub_url);
        assert!(header2.contains("token=xyz"));

        let other_url = Url::parse("https://other.com/").unwrap();
        let header3 = jar.get_cookie_header(&other_url);
        assert!(header3.is_empty());
    }

    #[test]
    fn test_cdp_cookie_with_leading_dot_domain_matches_requests() {
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "token".to_string(),
            value: "xyz".to_string(),
            domain: ".example.com".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: None,
        }]);

        let apex_url = Url::parse("https://example.com/").unwrap();
        let apex_header = jar.get_cookie_header(&apex_url);
        assert!(apex_header.contains("token=xyz"));

        let subdomain_url = Url::parse("https://api.example.com/").unwrap();
        let subdomain_header = jar.get_cookie_header(&subdomain_url);
        assert!(subdomain_header.contains("token=xyz"));

        let other_url = Url::parse("https://other.com/").unwrap();
        let other_header = jar.get_cookie_header(&other_url);
        assert!(other_header.is_empty());
    }

    #[test]
    fn test_secure_cookie_not_sent_over_http() {
        let jar = CookieJar::new();
        let https_url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("secure_token=secret; Secure", &https_url);

        let http_url = Url::parse("http://example.com/").unwrap();
        let header = jar.get_cookie_header(&http_url);
        assert!(header.is_empty());
    }

    #[test]
    fn test_max_age_zero_deletes_cookie() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("session=abc", &url);
        assert!(jar.get_cookie_header(&url).contains("session=abc"));

        jar.set_cookie("session=abc; Max-Age=0", &url);
        assert!(jar.get_cookie_header(&url).is_empty());
    }

    #[test]
    fn test_max_age_sets_expiry() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("token=xyz; Max-Age=3600", &url);
        assert!(jar.get_cookie_header(&url).contains("token=xyz"));
    }

    #[test]
    fn test_expired_cookie_not_sent() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("old=gone; Expires=Thu, 01 Jan 2020 00:00:00 GMT", &url);
        assert!(jar.get_cookie_header(&url).is_empty());
    }

    #[test]
    fn test_samesite_parsed() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("strict_cookie=val; SameSite=Strict", &url);
        assert!(jar.get_cookie_header(&url).contains("strict_cookie=val"));
    }

    #[test]
    fn test_clear_cookies() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("a=1", &url);
        assert!(!jar.get_cookie_header(&url).is_empty());

        jar.clear();
        assert!(jar.get_cookie_header(&url).is_empty());
    }

    #[test]
    fn test_set_cookies_from_cdp_preserves_same_site_and_expires() {
        let jar = CookieJar::new();
        let future_expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600;
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "sid".to_string(),
            value: "abc".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            secure: true,
            http_only: true,
            same_site: "Strict".to_string(),
            expires: Some(future_expiry),
        }]);

        let cookies = jar.get_all_cookies();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].same_site, "Strict");
        assert_eq!(cookies[0].expires, Some(future_expiry));
    }

    #[test]
    fn test_set_cookies_from_cdp_session_when_expires_none() {
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "n".to_string(),
            value: "v".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: None,
        }]);
        let cookies = jar.get_all_cookies();
        assert_eq!(cookies[0].expires, None);
        assert_eq!(cookies[0].same_site, DEFAULT_SAME_SITE);
    }

    #[test]
    fn test_delete_cookies_filtered_path_mismatch_preserves_cookie() {
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "sid".to_string(),
            value: "v".to_string(),
            domain: "example.com".to_string(),
            path: "/admin".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: None,
        }]);
        jar.delete_cookies_filtered("sid", "example.com", Some("/other"));
        assert_eq!(jar.get_all_cookies().len(), 1);

        jar.delete_cookies_filtered("sid", "example.com", Some("/admin"));
        assert!(jar.get_all_cookies().is_empty());
    }

    #[test]
    fn test_delete_cookies_filtered_no_path_deletes_regardless() {
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "sid".to_string(),
            value: "v".to_string(),
            domain: "example.com".to_string(),
            path: "/admin".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: None,
        }]);
        jar.delete_cookies_filtered("sid", "example.com", None);
        assert!(jar.get_all_cookies().is_empty());
    }

    #[test]
    fn test_set_cookies_from_cdp_expired_does_not_persist() {
        let jar = CookieJar::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "old".to_string(),
            value: "v".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: Some(now - 1),
        }]);
        let url = Url::parse("https://example.com/").unwrap();
        assert!(jar.get_cookie_header(&url).is_empty());
    }

    #[test]
    fn test_save_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cookies.json");

        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("session=abc123; Domain=example.com; Path=/", &url);
        jar.set_cookie("token=xyz; Secure; HttpOnly", &url);

        jar.save_to_file(&path).unwrap();
        assert!(path.exists());

        let jar2 = CookieJar::new();
        let count = jar2.load_from_file(&path).unwrap();
        assert_eq!(count, 2);

        let header = jar2.get_cookie_header(&url);
        assert!(header.contains("session=abc123"));
        assert!(header.contains("token=xyz"));
    }

    #[test]
    fn test_load_nonexistent_file_returns_zero() {
        let jar = CookieJar::new();
        let count = jar
            .load_from_file(std::path::Path::new("/nonexistent/cookies.json"))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_domain_matches_subdomain_without_leading_dot() {
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "session".to_string(),
            value: "abc".to_string(),
            domain: "xiaohongshu.com".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: true,
            same_site: String::new(),
            expires: None,
        }]);
        let url = Url::parse("https://www.xiaohongshu.com/explore").unwrap();
        let header = jar.get_cookie_header(&url);
        assert!(header.contains("session=abc"), "Cookie header was: '{}'", header);
    }

    #[test]
    fn test_cookie_from_file_load_then_send_in_request() {
        // Simulate what happens: load cookies from file → navigate → cookie should be in request
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cookies.json");
        
        // Write cookies like we exported from Chrome
        let cookies = serde_json::json!([
            {"name": "a1", "value": "testval", "domain": "xiaohongshu.com", "path": "/", "secure": false, "httpOnly": false},
            {"name": "web_session", "value": "sess123", "domain": "xiaohongshu.com", "path": "/", "secure": false, "httpOnly": true},
        ]);
        std::fs::write(&path, serde_json::to_string(&cookies).unwrap()).unwrap();
        
        let jar = CookieJar::new();
        let count = jar.load_from_file(&path).unwrap();
        assert_eq!(count, 2, "Should load 2 cookies");
        
        let url = Url::parse("https://www.xiaohongshu.com/explore").unwrap();
        let header = jar.get_cookie_header(&url);
        assert!(header.contains("a1=testval"), "Missing a1 in: '{}'", header);
        assert!(header.contains("web_session=sess123"), "Missing web_session in: '{}'", header);
    }

    // ── COOK-01: Domain= scoping validation ──────────────────────────────────

    #[test]
    fn cook01_rejects_cross_site_domain_injection() {
        let jar = CookieJar::new();
        let evil = Url::parse("https://evil.example/").unwrap();
        // A page / response on evil.example must not set a cookie for victim.com.
        jar.set_cookie_from_js("sid=attacker; Domain=victim.com; Path=/", &evil);
        jar.set_cookie("sid2=attacker; Domain=victim.com", &evil);
        let victim = Url::parse("https://victim.com/").unwrap();
        assert!(
            jar.get_cookie_header(&victim).is_empty(),
            "cross-site Domain= cookie must be rejected"
        );
        assert!(jar.get_all_cookies().is_empty());
    }

    #[test]
    fn cook01_rejects_public_suffix_domain() {
        let jar = CookieJar::new();
        jar.set_cookie_from_js(
            "a=1; Domain=co.uk",
            &Url::parse("https://shop.example.co.uk/").unwrap(),
        );
        jar.set_cookie_from_js("b=2; Domain=com", &Url::parse("https://evil.com/").unwrap());
        assert!(
            jar.get_all_cookies().is_empty(),
            "public-suffix Domain= cookies must be rejected"
        );
    }

    #[test]
    fn cook01_allows_legitimate_parent_and_host_only() {
        let jar = CookieJar::new();
        // Parent domain the host is under: allowed and shared with siblings.
        jar.set_cookie_from_js(
            "ok=1; Domain=example.com",
            &Url::parse("https://www.example.com/").unwrap(),
        );
        let api = Url::parse("https://api.example.com/").unwrap();
        assert!(jar.get_cookie_header(&api).contains("ok=1"));
        // Host-only cookie (no Domain=) on a single-label host still works.
        let local = Url::parse("http://localhost:3000/").unwrap();
        jar.set_cookie_from_js("h=2", &local);
        assert!(jar.get_cookie_header(&local).contains("h=2"));
    }

    // ── COOK-CDP-INJECT-1 / COOK-03: programmatic ingestion scope ────────────

    fn cdp_cookie(name: &str, domain: &str, path: &str, secure: bool) -> CookieInfo {
        CookieInfo {
            name: name.to_string(),
            value: "x".to_string(),
            domain: domain.to_string(),
            path: path.to_string(),
            secure,
            http_only: false,
            same_site: String::new(),
            expires: None,
        }
    }

    #[test]
    fn cdp_ingestion_rejects_public_suffix_and_bare_tld() {
        let jar = CookieJar::new();
        for dom in ["com", "co.uk", "azurewebsites.net", ".com"] {
            jar.set_cookies_from_cdp(vec![cdp_cookie("track", dom, "/", false)]);
        }
        assert!(
            jar.get_all_cookies().is_empty(),
            "public-suffix / bare-TLD CDP cookies must be dropped, got {:?}",
            jar.get_all_cookies()
        );
        // A registrable domain is still accepted.
        jar.set_cookies_from_cdp(vec![cdp_cookie("ok", "example.com", "/", false)]);
        assert_eq!(jar.get_all_cookies().len(), 1);
    }

    #[test]
    fn cdp_ingestion_enforces_cookie_prefixes() {
        let jar = CookieJar::new();
        // __Host-/__Secure- without the Secure flag are rejected.
        jar.set_cookies_from_cdp(vec![cdp_cookie("__Host-sid", "example.com", "/", false)]);
        jar.set_cookies_from_cdp(vec![cdp_cookie("__Secure-sid", "example.com", "/", false)]);
        // __Host- with a non-root path is rejected.
        jar.set_cookies_from_cdp(vec![cdp_cookie("__Host-sid", "example.com", "/admin", true)]);
        assert!(jar.get_all_cookies().is_empty(), "got {:?}", jar.get_all_cookies());
        // Valid __Host- (Secure, host-only, Path=/) is kept.
        jar.set_cookies_from_cdp(vec![cdp_cookie("__Host-sid", "example.com", "/", true)]);
        assert_eq!(jar.get_all_cookies().len(), 1);
    }

    // ── COOK-PREFIX-MISSING: header / document.cookie paths ──────────────────

    #[test]
    fn set_cookie_enforces_prefixes() {
        let jar = CookieJar::new();
        let https = Url::parse("https://example.com/").unwrap();
        let http = Url::parse("http://example.com/").unwrap();
        jar.set_cookie("__Secure-a=1", &https); // missing Secure flag
        jar.set_cookie("__Secure-b=1; Secure", &http); // not a secure transport
        jar.set_cookie("__Host-c=1; Secure; Domain=example.com; Path=/", &https); // not host-only
        jar.set_cookie("__Host-d=1; Secure; Path=/admin", &https); // path != /
        assert!(
            jar.get_all_cookies().is_empty(),
            "invalid prefixed cookies must be dropped, got {:?}",
            jar.get_all_cookies()
        );
        jar.set_cookie("__Secure-e=1; Secure", &https);
        jar.set_cookie("__Host-f=1; Secure; Path=/", &https);
        assert_eq!(jar.get_all_cookies().len(), 2);
    }

    #[test]
    fn set_cookie_rejects_private_cloud_suffix() {
        // COOK-PSL-HARDCODED-GAPS: a cloud PRIVATE suffix must be rejected so one
        // tenant cannot scope a cookie across every other tenant.
        let jar = CookieJar::new();
        jar.set_cookie_from_js(
            "shared=evil; Domain=azurewebsites.net",
            &Url::parse("https://evil.azurewebsites.net/").unwrap(),
        );
        assert!(jar.get_all_cookies().is_empty());
    }

    // ── COOK-PATH-BOUND-1: RFC 6265 §5.1.4 path-match boundary ───────────────

    #[test]
    fn cookie_path_match_respects_directory_boundary() {
        let jar = CookieJar::new();
        jar.set_cookie("sid=1; Path=/admin", &Url::parse("https://example.com/admin").unwrap());
        let leak = jar.get_cookie_header(&Url::parse("https://example.com/administrator").unwrap());
        assert!(!leak.contains("sid=1"), "Path=/admin must not leak to /administrator, got '{}'", leak);
        assert!(jar
            .get_cookie_header(&Url::parse("https://example.com/admin").unwrap())
            .contains("sid=1"));
        assert!(jar
            .get_cookie_header(&Url::parse("https://example.com/admin/users").unwrap())
            .contains("sid=1"));
    }

    // ── COOK-04: SameSite enforced at egress ─────────────────────────────────

    #[test]
    fn cook04_samesite_enforced_at_egress() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("strict=s; SameSite=Strict; Secure", &url);
        jar.set_cookie("lax=l; SameSite=Lax; Secure", &url);
        jar.set_cookie("nonec=n; SameSite=None; Secure", &url);

        // Default / same-site: every cookie is sent (legacy behaviour preserved).
        let same = jar.get_cookie_header(&url);
        assert!(same.contains("strict=s") && same.contains("lax=l") && same.contains("nonec=n"));

        // Cross-site top-level navigation: Strict withheld, Lax + None sent.
        let top = jar.get_cookie_header_ctx(&url, SameSiteContext::CrossSiteTopLevel);
        assert!(!top.contains("strict=s"), "Strict must be withheld cross-site, got '{}'", top);
        assert!(top.contains("lax=l") && top.contains("nonec=n"));

        // Cross-site subresource / unsafe method: only None is sent.
        let cross = jar.get_cookie_header_ctx(&url, SameSiteContext::CrossSite);
        assert!(!cross.contains("strict=s") && !cross.contains("lax=l"), "got '{}'", cross);
        assert!(cross.contains("nonec=n"));
    }

    #[test]
    fn same_site_registrable_domain_comparison() {
        let u = |s: &str| Url::parse(s).unwrap();
        // Same registrable domain across subdomains / scheme / port.
        assert!(is_same_site(&u("https://www.example.com/"), &u("https://api.example.com/")));
        assert!(is_same_site(&u("http://example.com:80/"), &u("https://example.com/")));
        // Different registrable domains.
        assert!(!is_same_site(&u("https://bank.com/"), &u("https://evil.com/")));
        // Cross-tenant under a PRIVATE public suffix is NOT same-site.
        assert!(!is_same_site(
            &u("https://a.azurewebsites.net/"),
            &u("https://b.azurewebsites.net/")
        ));
        // Same tenant under a multi-label suffix IS same-site.
        assert!(is_same_site(&u("https://x.shop.co.uk/"), &u("https://y.shop.co.uk/")));
        assert!(!is_same_site(&u("https://shop.co.uk/"), &u("https://other.co.uk/")));
    }
}
