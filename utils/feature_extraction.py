from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
import concurrent.futures
import ipaddress
import logging
import re
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
except Exception:  # pragma: no cover
    BeautifulSoup = None

import pandas as pd
import requests

try:
    import whois
except Exception:  # pragma: no cover
    whois = None


PHISHING = -1
UNKNOWN = 0
LEGITIMATE = 1

DEFAULT_HTTP_TIMEOUT = 4
DEFAULT_SOCKET_TIMEOUT = 3
USER_AGENT = "PhishGuard/3.0 (+Flask portfolio app)"

CANONICAL_FEATURES = [
    "having_ip_address",
    "url_length",
    "shortining_service",
    "having_at_symbol",
    "double_slash_redirecting",
    "prefix_suffix",
    "having_sub_domain",
    "sslfinal_state",
    "domain_registeration_length",
    "favicon",
    "port",
    "https_token",
    "request_url",
    "url_of_anchor",
    "links_in_tags",
    "sfh",
    "submitting_to_email",
    "abnormal_url",
    "redirect",
    "on_mouseover",
    "rightclick",
    "popupwidnow",
    "iframe",
    "age_of_domain",
    "dnsrecord",
    "web_traffic",
    "page_rank",
    "google_index",
    "links_pointing_to_page",
    "statistical_report",
]

FEATURE_METADATA = {
    "having_ip_address": {"label": "IP address in URL", "description": "Phishing URLs often use raw IP addresses instead of trusted domain names."},
    "url_length": {"label": "URL length", "description": "Long URLs are more likely to hide misleading paths or brand names."},
    "shortining_service": {"label": "Shortened URL", "description": "Shorteners can hide the real destination domain."},
    "having_at_symbol": {"label": "@ symbol", "description": "The @ character can obscure the destination in a URL."},
    "double_slash_redirecting": {"label": "Extra // redirect pattern", "description": "Unexpected double slashes inside the path can be used for misleading redirects."},
    "prefix_suffix": {"label": "Hyphenated domain", "description": "Brand impersonation often appears in domains that add prefixes or suffixes."},
    "having_sub_domain": {"label": "Subdomain depth", "description": "Many nested subdomains can be used to mimic a real brand."},
    "sslfinal_state": {"label": "HTTPS / SSL state", "description": "Valid HTTPS is a positive trust signal, though not a guarantee of safety."},
    "domain_registeration_length": {"label": "Registration length", "description": "Very short registration periods are more common in disposable phishing domains."},
    "favicon": {"label": "Favicon source", "description": "Loading the icon from another domain can be suspicious."},
    "port": {"label": "Network port", "description": "Unusual ports may indicate an untrusted or unusual setup."},
    "https_token": {"label": "Fake https token", "description": "Placing 'https' inside the hostname can be a social-engineering trick."},
    "request_url": {"label": "Embedded resources", "description": "Pages that pull many resources from other domains can be riskier."},
    "url_of_anchor": {"label": "Anchor behavior", "description": "Unsafe or empty links can signal deceptive page behavior."},
    "links_in_tags": {"label": "External tag links", "description": "A high share of off-domain script or stylesheet links may be suspicious."},
    "sfh": {"label": "Form handler", "description": "Blank or unsafe form actions are common on credential-harvesting pages."},
    "submitting_to_email": {"label": "Email submission", "description": "Pages that submit forms directly to email are suspicious."},
    "abnormal_url": {"label": "Abnormal URL pattern", "description": "Credentials in the URL or domain inconsistencies can be signs of abuse."},
    "redirect": {"label": "Redirect behavior", "description": "Too many redirects or redirects to another host can increase risk."},
    "on_mouseover": {"label": "Mouseover scripts", "description": "Some phishing pages use mouseover tricks to hide real actions."},
    "rightclick": {"label": "Right-click blocking", "description": "Disabling right click can be used to frustrate inspection."},
    "popupwidnow": {"label": "Popup behavior", "description": "Popup windows are sometimes used in fake login or alert flows."},
    "iframe": {"label": "Iframe usage", "description": "Hidden or tiny iframes can be abused for deceptive content."},
    "age_of_domain": {"label": "Domain age", "description": "Newly created domains are riskier than well-established domains."},
    "dnsrecord": {"label": "DNS record", "description": "A resolvable domain is a basic legitimacy signal."},
    "web_traffic": {"label": "Traffic reputation", "description": "External reputation signals were minimized for reliability and privacy."},
    "page_rank": {"label": "Page rank", "description": "Page-rank style checks were minimized to avoid brittle third-party calls."},
    "google_index": {"label": "Search indexing", "description": "Search-index checks were minimized to avoid scraping external services."},
    "links_pointing_to_page": {"label": "Inbound links", "description": "Backlink-style signals were minimized to avoid external dependencies."},
    "statistical_report": {"label": "Suspicious pattern report", "description": "Known suspicious lexical patterns can increase risk."},
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "tiny.cc",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
}

SUSPICIOUS_KEYWORDS = ("login", "verify", "secure", "update", "account", "signin", "confirm", "banking")
SPECIAL_CHARACTERS = "@?=&_%#!"
MULTIPART_SUFFIXES = {"co.uk", "org.uk", "gov.uk", "ac.uk", "co.in", "com.au", "co.jp"}

LOGGER = logging.getLogger(__name__)
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})


@dataclass
class WebObservation:
    response: requests.Response | None
    final_url: str
    final_hostname: str
    history_count: int
    text: str
    soup: Any
    error: str | None = None


@dataclass
class FeatureExtractionResult:
    input_url: str
    normalized_url: str
    hostname: str
    features: dict[str, int]
    display_metrics: dict[str, Any]
    feature_details: dict[str, str]
    suspicious_indicators: list[str]
    warnings: list[str]
    lexical_overview: dict[str, Any]


def normalize_url(raw_url: str, auto_https: bool = True) -> str:
    if not raw_url or not raw_url.strip():
        raise ValueError("Please enter a URL.")

    url = raw_url.strip()
    if auto_https and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"https://{url}"

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("The URL is missing a hostname.")

    hostname = parsed.hostname.strip(".")
    if "." not in hostname and not _is_ip_address(hostname) and hostname.lower() != "localhost":
        raise ValueError("The URL hostname does not look valid.")

    return url


def build_feature_table(extraction: FeatureExtractionResult) -> pd.DataFrame:
    rows = []
    for feature_name in CANONICAL_FEATURES:
        rows.append(
            {
                "feature": FEATURE_METADATA[feature_name]["label"],
                "signal": _label_for_value(extraction.features[feature_name]),
                "value": extraction.features[feature_name],
                "observed": extraction.feature_details.get(feature_name, "Not available"),
                "description": FEATURE_METADATA[feature_name]["description"],
            }
        )
    return pd.DataFrame(rows)


def prepare_model_frame(extraction: FeatureExtractionResult, expected_features: list[str] | None = None) -> pd.DataFrame:
    expected = expected_features or CANONICAL_FEATURES
    row = {feature_name: extraction.features.get(feature_name, UNKNOWN) for feature_name in expected}
    return pd.DataFrame([row], columns=expected)


def extract_features(url: str) -> FeatureExtractionResult:
    normalized_url = normalize_url(url)
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    observation = _fetch_observation(normalized_url)
    domain_info = _safe_whois(hostname)
    dns_resolution = _resolve_hostname(hostname)
    ssl_state = _check_ssl_state(hostname) if parsed.scheme == "https" else {"valid": False, "error": "not_https"}

    features: dict[str, int] = {}
    details: dict[str, str] = {}
    warnings: list[str] = []
    suspicious_indicators: list[str] = []

    registered_domain = _registered_domain(hostname)
    url_length = len(normalized_url)
    subdomain_depth = _subdomain_depth(hostname)
    domain_age_months = _domain_age_in_months(domain_info)
    registration_days = _registration_length_days(domain_info)

    lexical_overview = {
        "url_length": url_length,
        "dot_count": normalized_url.count("."),
        "subdomain_count": subdomain_depth,
        "digit_count": sum(character.isdigit() for character in normalized_url),
        "hyphen_count": normalized_url.count("-"),
        "special_char_count": sum(character in SPECIAL_CHARACTERS for character in normalized_url),
        "uses_https": parsed.scheme == "https",
        "has_ip_address": _is_ip_address(hostname),
        "suspicious_keywords": [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in normalized_url.lower()],
    }

    features["having_ip_address"] = PHISHING if lexical_overview["has_ip_address"] else LEGITIMATE
    details["having_ip_address"] = "Hostname is a raw IP address." if features["having_ip_address"] == PHISHING else "Hostname uses a domain name."

    features["url_length"] = PHISHING if url_length > 75 else UNKNOWN if url_length >= 54 else LEGITIMATE
    details["url_length"] = f"{url_length} characters."
    if features["url_length"] == PHISHING:
        suspicious_indicators.append(f"The URL is quite long ({url_length} characters).")

    features["shortining_service"] = PHISHING if hostname.lower() in SHORTENER_DOMAINS else LEGITIMATE
    details["shortining_service"] = f"Detected hostname: {hostname.lower()}."

    features["having_at_symbol"] = PHISHING if "@" in normalized_url else LEGITIMATE
    details["having_at_symbol"] = "Contains @ in the URL." if features["having_at_symbol"] == PHISHING else "No @ symbol detected."
    if features["having_at_symbol"] == PHISHING:
        suspicious_indicators.append("The URL contains an @ symbol, which can obscure the true destination.")

    after_scheme = normalized_url.split("://", maxsplit=1)[-1]
    features["double_slash_redirecting"] = PHISHING if "//" in after_scheme else LEGITIMATE
    details["double_slash_redirecting"] = "Extra // found after the scheme." if features["double_slash_redirecting"] == PHISHING else "No unexpected double slash pattern found."

    features["prefix_suffix"] = PHISHING if "-" in hostname else LEGITIMATE
    details["prefix_suffix"] = f"Hostname: {hostname}."
    if features["prefix_suffix"] == PHISHING:
        suspicious_indicators.append("The hostname contains a hyphenated brand-style pattern.")

    features["having_sub_domain"] = LEGITIMATE if subdomain_depth <= 1 else UNKNOWN if subdomain_depth == 2 else PHISHING
    details["having_sub_domain"] = f"Subdomain depth: {subdomain_depth}."

    if parsed.scheme != "https":
        features["sslfinal_state"] = PHISHING
    elif ssl_state["valid"]:
        features["sslfinal_state"] = LEGITIMATE
    else:
        features["sslfinal_state"] = UNKNOWN
        warnings.append("SSL certificate validation could not be fully confirmed.")
    details["sslfinal_state"] = "HTTPS with a reachable certificate." if features["sslfinal_state"] == LEGITIMATE else "HTTPS not confirmed with a reachable certificate."

    if registration_days is None:
        features["domain_registeration_length"] = UNKNOWN
        details["domain_registeration_length"] = "WHOIS registration dates unavailable."
        warnings.append("Registration-length lookup was unavailable.")
    else:
        features["domain_registeration_length"] = LEGITIMATE if registration_days > 365 else PHISHING
        details["domain_registeration_length"] = f"Approximate registration length: {registration_days} days."

    favicon_state, favicon_detail = _favicon_state(observation, hostname)
    features["favicon"] = favicon_state
    details["favicon"] = favicon_detail

    features["port"] = LEGITIMATE if parsed.port in {None, 80, 443} else PHISHING
    details["port"] = "Default HTTP/HTTPS port." if features["port"] == LEGITIMATE else f"Uses non-standard port {parsed.port}."

    features["https_token"] = PHISHING if "https" in hostname.lower() else LEGITIMATE
    details["https_token"] = "Hostname contains the word 'https'." if features["https_token"] == PHISHING else "No misleading 'https' token in hostname."

    request_state, request_detail, anchor_state, anchor_detail, links_state, links_detail, sfh_state, sfh_detail = _html_link_signals(
        observation, hostname
    )
    features["request_url"] = request_state
    details["request_url"] = request_detail
    features["url_of_anchor"] = anchor_state
    details["url_of_anchor"] = anchor_detail
    features["links_in_tags"] = links_state
    details["links_in_tags"] = links_detail
    features["sfh"] = sfh_state
    details["sfh"] = sfh_detail

    submit_state, submit_detail = _submitting_to_email(observation)
    features["submitting_to_email"] = submit_state
    details["submitting_to_email"] = submit_detail

    abnormal_state, abnormal_detail = _abnormal_url_state(parsed, hostname, registered_domain)
    features["abnormal_url"] = abnormal_state
    details["abnormal_url"] = abnormal_detail

    redirect_state, redirect_detail = _redirect_state(observation, hostname)
    features["redirect"] = redirect_state
    details["redirect"] = redirect_detail

    mouseover_state, mouseover_detail = _contains_text_pattern(observation, ["onmouseover"], "Mouseover script markers detected.", "No mouseover script tricks detected.")
    features["on_mouseover"] = mouseover_state
    details["on_mouseover"] = mouseover_detail

    rightclick_state, rightclick_detail = _contains_text_pattern(
        observation,
        ["event.button==2", "contextmenu", "preventdefault"],
        "Right-click blocking markers detected.",
        "No right-click blocking markers detected.",
    )
    features["rightclick"] = rightclick_state
    details["rightclick"] = rightclick_detail

    popup_state, popup_detail = _contains_text_pattern(observation, ["window.open", "popup"], "Popup script markers detected.", "No popup script markers detected.")
    features["popupwidnow"] = popup_state
    details["popupwidnow"] = popup_detail

    iframe_state, iframe_detail = _iframe_state(observation)
    features["iframe"] = iframe_state
    details["iframe"] = iframe_detail

    if domain_age_months is None:
        features["age_of_domain"] = UNKNOWN
        details["age_of_domain"] = "WHOIS creation date unavailable."
        warnings.append("Domain age lookup was unavailable.")
    else:
        features["age_of_domain"] = LEGITIMATE if domain_age_months >= 6 else PHISHING
        details["age_of_domain"] = f"Approximate age: {domain_age_months} months."

    if dns_resolution["resolves"] is True:
        features["dnsrecord"] = LEGITIMATE
        details["dnsrecord"] = f"Domain resolved to {dns_resolution['address']}."
    elif dns_resolution["resolves"] is False:
        features["dnsrecord"] = PHISHING
        details["dnsrecord"] = "Domain did not resolve in DNS."
    else:
        features["dnsrecord"] = UNKNOWN
        details["dnsrecord"] = "DNS lookup was unavailable."
        warnings.append("DNS lookup was unavailable.")

    lexical_state = _statistical_pattern_state(normalized_url, hostname)
    features["statistical_report"] = lexical_state["state"]
    details["statistical_report"] = lexical_state["detail"]

    for feature_name in ("web_traffic", "page_rank", "google_index", "links_pointing_to_page"):
        features[feature_name] = UNKNOWN
        details[feature_name] = "External reputation check intentionally skipped for reliability and privacy."

    suspicious_indicators.extend(_collect_suspicious_indicators(features, details, lexical_overview))
    if observation.error:
        warnings.append(f"Page content could not be fetched: {observation.error}")

    display_metrics = {
        "Normalized URL": normalized_url,
        "Hostname": hostname,
        "Registered domain": registered_domain,
        "URL length": url_length,
        "Dot count": lexical_overview["dot_count"],
        "Subdomains": subdomain_depth,
        "Uses HTTPS": "Yes" if lexical_overview["uses_https"] else "No",
        "Digit count": lexical_overview["digit_count"],
        "Hyphen count": lexical_overview["hyphen_count"],
        "Special character count": lexical_overview["special_char_count"],
        "Suspicious keywords": ", ".join(lexical_overview["suspicious_keywords"]) or "None",
        "Redirects": observation.history_count,
        "Domain age (months)": domain_age_months if domain_age_months is not None else "Unavailable",
        "HTML fetched": "Yes" if observation.response is not None else "No",
    }

    return FeatureExtractionResult(
        input_url=url,
        normalized_url=normalized_url,
        hostname=hostname,
        features=features,
        display_metrics=display_metrics,
        feature_details=details,
        suspicious_indicators=list(dict.fromkeys(suspicious_indicators)),
        warnings=list(dict.fromkeys(warnings)),
        lexical_overview=lexical_overview,
    )


def _collect_suspicious_indicators(features: dict[str, int], details: dict[str, str], lexical_overview: dict[str, Any]) -> list[str]:
    indicators: list[str] = []
    if features["having_ip_address"] == PHISHING:
        indicators.append("The URL uses an IP address instead of a domain name.")
    if features["shortining_service"] == PHISHING:
        indicators.append("The link uses a shortened URL service.")
    if features["redirect"] == PHISHING:
        indicators.append("The request redirects in a suspicious way.")
    if features["age_of_domain"] == PHISHING:
        indicators.append("The domain appears to be very new.")
    if lexical_overview["suspicious_keywords"]:
        indicators.append(f"Suspicious keywords found: {', '.join(lexical_overview['suspicious_keywords'])}.")
    if features["dnsrecord"] == PHISHING:
        indicators.append("The hostname could not be resolved in DNS.")
    if features["having_sub_domain"] == PHISHING:
        indicators.append(details["having_sub_domain"])
    return indicators


def _label_for_value(value: int) -> str:
    return {PHISHING: "Suspicious", UNKNOWN: "Uncertain", LEGITIMATE: "Legitimate"}.get(value, "Unknown")


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _registered_domain(hostname: str) -> str:
    parts = hostname.lower().split(".")
    if len(parts) <= 2:
        return hostname.lower()
    suffix = ".".join(parts[-2:])
    if suffix in MULTIPART_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _subdomain_depth(hostname: str) -> int:
    registered = _registered_domain(hostname)
    if hostname == registered:
        return 0
    return max(0, len(hostname.split(".")) - len(registered.split(".")))


@lru_cache(maxsize=512)
def _fetch_observation(url: str) -> WebObservation:
    try:
        response = SESSION.get(url, timeout=DEFAULT_HTTP_TIMEOUT, allow_redirects=True)
        response.raise_for_status()
        text = response.text[:200000]
        soup = BeautifulSoup(text, "html.parser") if BeautifulSoup is not None else None
        return WebObservation(
            response=response,
            final_url=response.url,
            final_hostname=(urlparse(response.url).hostname or "").lower(),
            history_count=len(response.history),
            text=text,
            soup=soup,
        )
    except requests.RequestException as exc:
        return WebObservation(
            response=None,
            final_url=url,
            final_hostname=(urlparse(url).hostname or "").lower(),
            history_count=0,
            text="",
            soup=None,
            error=str(exc),
        )


@lru_cache(maxsize=512)
def _resolve_hostname(hostname: str) -> dict[str, Any]:
    try:
        socket.setdefaulttimeout(DEFAULT_SOCKET_TIMEOUT)
        return {"resolves": True, "address": socket.gethostbyname(hostname)}
    except socket.gaierror:
        return {"resolves": False, "address": None}
    except Exception as exc:  # pragma: no cover
        LOGGER.warning("DNS lookup failed for %s: %s", hostname, exc)
        return {"resolves": None, "address": None}


@lru_cache(maxsize=256)
def _check_ssl_state(hostname: str) -> dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=DEFAULT_SOCKET_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as wrapped:
                return {"valid": bool(wrapped.getpeercert())}
    except Exception as exc:  # pragma: no cover
        LOGGER.warning("SSL validation failed for %s: %s", hostname, exc)
        return {"valid": False, "error": str(exc)}


@lru_cache(maxsize=256)
def _safe_whois(hostname: str) -> Any:
    if whois is None:
        return None

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(whois.whois, hostname)
    try:
        return future.result(timeout=DEFAULT_HTTP_TIMEOUT)
    except Exception as exc:  # pragma: no cover
        LOGGER.warning("WHOIS lookup failed for %s: %s", hostname, exc)
        return None
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _normalize_datetime(value: Any) -> datetime | None:
    if isinstance(value, list):
        value = next((item for item in value if isinstance(item, datetime)), value[0] if value else None)
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _domain_age_in_months(domain_info: Any) -> int | None:
    if not domain_info:
        return None
    created = _normalize_datetime(getattr(domain_info, "creation_date", None))
    if not created:
        return None
    now = datetime.now(timezone.utc)
    return max(0, (now.year - created.year) * 12 + (now.month - created.month))


def _registration_length_days(domain_info: Any) -> int | None:
    if not domain_info:
        return None
    created = _normalize_datetime(getattr(domain_info, "creation_date", None))
    expiry = _normalize_datetime(getattr(domain_info, "expiration_date", None))
    if not created or not expiry:
        return None
    return max(0, (expiry - created).days)


def _same_registered_domain(candidate: str, hostname: str) -> bool:
    candidate_host = urlparse(candidate).hostname or candidate
    return bool(candidate_host) and _registered_domain(candidate_host.lower()) == _registered_domain(hostname.lower())


def _favicon_state(observation: WebObservation, hostname: str) -> tuple[int, str]:
    if not observation.soup:
        return UNKNOWN, "Page content unavailable."
    icon = observation.soup.find("link", rel=lambda value: value and "icon" in " ".join(value).lower())
    if not icon or not icon.get("href"):
        return UNKNOWN, "No favicon link found."
    href = icon.get("href", "")
    if href.startswith("/") or _same_registered_domain(href, hostname):
        return LEGITIMATE, "Favicon appears to load from the same site or a relative path."
    return PHISHING, "Favicon appears to load from another domain."


def _html_link_signals(observation: WebObservation, hostname: str) -> tuple[int, str, int, str, int, str, int, str]:
    if not observation.soup:
        unavailable = "Page content unavailable."
        return UNKNOWN, unavailable, UNKNOWN, unavailable, UNKNOWN, unavailable, UNKNOWN, unavailable

    anchors = observation.soup.find_all("a")
    resources = observation.soup.find_all(["img", "script", "link"])
    forms = observation.soup.find_all("form")

    suspicious_anchors = 0
    for anchor in anchors:
        href = (anchor.get("href") or "").strip().lower()
        if not href or href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
            suspicious_anchors += 1

    anchor_ratio = suspicious_anchors / len(anchors) if anchors else 0
    anchor_state = UNKNOWN if not anchors else PHISHING if anchor_ratio > 0.67 else UNKNOWN if anchor_ratio >= 0.31 else LEGITIMATE
    anchor_detail = "No anchor tags found." if not anchors else f"Suspicious anchors: {suspicious_anchors}/{len(anchors)}."

    external_resources = 0
    total_resources = 0
    external_links = 0
    total_links = 0

    for tag in resources:
        attr = tag.get("src") or tag.get("href")
        if not attr:
            continue
        total_resources += 1
        if attr.startswith("http") and not _same_registered_domain(attr, hostname):
            external_resources += 1
        if tag.name in {"script", "link"}:
            total_links += 1
            if attr.startswith("http") and not _same_registered_domain(attr, hostname):
                external_links += 1

    request_ratio = external_resources / total_resources if total_resources else 0
    request_state = UNKNOWN if total_resources == 0 else PHISHING if request_ratio > 0.61 else UNKNOWN if request_ratio >= 0.22 else LEGITIMATE
    request_detail = "No embedded resource tags found." if total_resources == 0 else f"External resources: {external_resources}/{total_resources}."

    links_ratio = external_links / total_links if total_links else 0
    links_state = UNKNOWN if total_links == 0 else PHISHING if links_ratio > 0.81 else UNKNOWN if links_ratio >= 0.17 else LEGITIMATE
    links_detail = "No script/link tags with URLs found." if total_links == 0 else f"External script/link tags: {external_links}/{total_links}."

    if not forms:
        return request_state, request_detail, anchor_state, anchor_detail, links_state, links_detail, UNKNOWN, "No forms found."

    blank_or_external = 0
    for form in forms:
        action = (form.get("action") or "").strip().lower()
        if not action or action == "about:blank" or action.startswith("mailto:"):
            blank_or_external += 1
            continue
        if action.startswith("http") and not _same_registered_domain(action, hostname):
            blank_or_external += 1

    ratio = blank_or_external / len(forms)
    sfh_state = PHISHING if ratio > 0.5 else UNKNOWN if ratio > 0 else LEGITIMATE
    sfh_detail = f"Unsafe form actions: {blank_or_external}/{len(forms)}."
    return request_state, request_detail, anchor_state, anchor_detail, links_state, links_detail, sfh_state, sfh_detail


def _submitting_to_email(observation: WebObservation) -> tuple[int, str]:
    if not observation.soup:
        return UNKNOWN, "Page content unavailable."
    forms = observation.soup.find_all("form")
    for form in forms:
        action = (form.get("action") or "").strip().lower()
        if action.startswith("mailto:"):
            return PHISHING, "Found a form action that submits to an email address."
    return (LEGITIMATE, "No email-based form submission detected.") if forms else (UNKNOWN, "No forms found.")


def _abnormal_url_state(parsed, hostname: str, registered_domain: str) -> tuple[int, str]:
    if parsed.username or parsed.password:
        return PHISHING, "The URL includes embedded credentials."
    if registered_domain and not hostname.lower().endswith(registered_domain.lower()):
        return PHISHING, "Hostname does not match the registered domain pattern."
    if hostname.startswith("xn--"):
        return UNKNOWN, "Hostname uses punycode."
    return LEGITIMATE, "No abnormal URL pattern detected."


def _redirect_state(observation: WebObservation, hostname: str) -> tuple[int, str]:
    if not observation.response:
        return UNKNOWN, "Redirect behavior unavailable because the page could not be fetched."
    if observation.final_hostname and _registered_domain(observation.final_hostname) != _registered_domain(hostname):
        return PHISHING, f"Final host differs from input host: {observation.final_hostname}."
    if observation.history_count > 2:
        return PHISHING, f"Redirect count: {observation.history_count}."
    if observation.history_count > 0:
        return UNKNOWN, f"Redirect count: {observation.history_count}."
    return LEGITIMATE, "No redirects observed."


def _contains_text_pattern(observation: WebObservation, patterns: list[str], hit_message: str, miss_message: str) -> tuple[int, str]:
    if not observation.text:
        return UNKNOWN, "Page content unavailable."
    text = observation.text.lower()
    return (PHISHING, hit_message) if any(pattern.lower() in text for pattern in patterns) else (LEGITIMATE, miss_message)


def _iframe_state(observation: WebObservation) -> tuple[int, str]:
    if not observation.soup:
        return UNKNOWN, "Page content unavailable."
    iframes = observation.soup.find_all("iframe")
    if not iframes:
        return LEGITIMATE, "No iframe tags detected."
    for iframe in iframes:
        width = str(iframe.get("width", "")).strip()
        height = str(iframe.get("height", "")).strip()
        if iframe.get("frameborder") == "0" or width in {"0", "1"} or height in {"0", "1"}:
            return PHISHING, "Hidden or very small iframe detected."
    return UNKNOWN, f"{len(iframes)} iframe tag(s) detected."


def _statistical_pattern_state(url: str, hostname: str) -> dict[str, Any]:
    digit_ratio = sum(character.isdigit() for character in hostname) / max(len(hostname), 1)
    if digit_ratio > 0.35:
        return {"state": PHISHING, "detail": "Hostname contains an unusually high number of digits."}
    if any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS) and "-" in hostname:
        return {"state": PHISHING, "detail": "URL combines phishing-like keywords with a hyphenated hostname."}
    return {"state": LEGITIMATE, "detail": "No strong lexical phishing pattern detected."}
