import json
import mimetypes
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock

BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "templates" / "index.html"
STATIC_DIR = BASE_DIR / "static"

HOST = "0.0.0.0"
PORT = 5000
MAX_WORKERS = 4
RDAP_TIMEOUT = 15
WHOIS_TIMEOUT = 15
RDAP_RETRIES = 3
MAX_URLS = 2000
IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/138 Safari/537.36"
)

rdap_bootstrap = {}
registrar_cache = {}
cache_lock = Lock()
whois_server_cache = {}
whois_lock = Lock()
bootstrap_lock = Lock()


def clean_urls(raw_text):
    urls = []
    seen = set()

    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue

        markdown_match = re.match(
            r"^\[(https?://[^\]]+)\]\((https?://[^)]+)\)$",
            line,
        )
        if markdown_match:
            line = markdown_match.group(2)

        if line not in seen:
            seen.add(line)
            urls.append(line)

    return urls


def get_hostname(url):
    value = url.strip()
    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urllib.parse.urlparse(value)
        hostname = parsed.hostname
        if not hostname:
            return None

        hostname = hostname.lower().strip(".")
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except Exception:
            pass
        return hostname
    except Exception:
        return None


def generate_domain_candidates(hostname):
    if not hostname:
        return []

    if hostname.startswith("www."):
        hostname = hostname[4:]

    labels = hostname.split(".")
    if len(labels) < 2:
        return []

    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def load_rdap_bootstrap(force=False):
    global rdap_bootstrap

    with bootstrap_lock:
        if rdap_bootstrap and not force:
            return True

        req = urllib.request.Request(
            IANA_RDAP_BOOTSTRAP,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=RDAP_TIMEOUT) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
        except Exception:
            return False

        mapping = {}
        for service in data.get("services", []):
            if len(service) < 2:
                continue
            suffixes, urls = service[0], service[1]
            if not urls:
                continue
            base_url = urls[0]
            for suffix in suffixes:
                mapping[suffix.lower()] = base_url

        rdap_bootstrap = mapping
        return bool(rdap_bootstrap)


def get_rdap_base(domain):
    if not domain:
        return None

    labels = domain.lower().split(".")
    for i in range(len(labels)):
        suffix = ".".join(labels[i:])
        if suffix in rdap_bootstrap:
            return rdap_bootstrap[suffix]
    return None


def get_vcard_field_values(entity, wanted_field):
    values = []
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return values

    fields = vcard[1]
    if not isinstance(fields, list):
        return values

    for field in fields:
        if not isinstance(field, list) or len(field) < 4:
            continue
        if str(field[0]).lower() != wanted_field.lower():
            continue

        value = field[3]
        if isinstance(value, list):
            value = " ".join(str(x) for x in value if x)

        value = str(value).strip()
        if value:
            values.append(value)

    return values


def get_vcard_name(entity):
    for wanted_field in ("fn", "org"):
        values = get_vcard_field_values(entity, wanted_field)
        if values:
            return values[0]
    return None


def get_vcard_emails(entity):
    emails = get_vcard_field_values(entity, "email")
    cleaned = []

    for email in emails:
        email = email.strip()
        if email.lower().startswith("mailto:"):
            email = email[7:]
        email = email.strip()
        if "@" in email and " " not in email:
            cleaned.append(email)

    return cleaned


def find_registrar_entity(entities):
    if not isinstance(entities, list):
        return None

    for entity in entities:
        if not isinstance(entity, dict):
            continue

        roles = [str(x).lower() for x in entity.get("roles", [])]
        if "registrar" in roles and get_vcard_name(entity):
            return entity

        found = find_registrar_entity(entity.get("entities", []))
        if found:
            return found

    return None


def find_email_in_entity_tree(entity):
    if not isinstance(entity, dict):
        return None

    emails = get_vcard_emails(entity)
    if emails:
        return emails[0]

    nested = entity.get("entities", [])
    if isinstance(nested, list):
        for child in nested:
            if not isinstance(child, dict):
                continue
            roles = [str(x).lower() for x in child.get("roles", [])]
            if "abuse" in roles:
                emails = get_vcard_emails(child)
                if emails:
                    return emails[0]

        for child in nested:
            email = find_email_in_entity_tree(child)
            if email:
                return email

    return None


def find_abuse_email_from_entities(entities):
    if not isinstance(entities, list):
        return None

    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = [str(x).lower() for x in entity.get("roles", [])]
        if "abuse" in roles:
            emails = get_vcard_emails(entity)
            if emails:
                return emails[0]
            email = find_email_in_entity_tree(entity)
            if email:
                return email

    for entity in entities:
        if not isinstance(entity, dict):
            continue
        email = find_abuse_email_from_entities(entity.get("entities", []))
        if email:
            return email

    return None


def extract_registrar_from_rdap(data):
    if not isinstance(data, dict):
        return None, None

    entities = data.get("entities", [])
    registrar_entity = find_registrar_entity(entities)
    registrar = None
    abuse_email = None

    if registrar_entity:
        registrar = get_vcard_name(registrar_entity)
        abuse_email = find_email_in_entity_tree(registrar_entity)

    if not abuse_email:
        abuse_email = find_abuse_email_from_entities(entities)

    return registrar, abuse_email


def rdap_query(domain):
    base_url = get_rdap_base(domain)
    if not base_url:
        return None, None, "NO_RDAP"

    query_url = base_url.rstrip("/") + "/domain/" + urllib.parse.quote(domain)

    for attempt in range(RDAP_RETRIES):
        req = urllib.request.Request(
            query_url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/rdap+json, application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=RDAP_TIMEOUT) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
                registrar, abuse_email = extract_registrar_from_rdap(data)
                if registrar:
                    return registrar, abuse_email, "RDAP"
                return None, abuse_email, "RDAP_NO_REGISTRAR"

        except urllib.error.HTTPError as exc:
            if exc.code in (400, 404):
                return None, None, "NOT_FOUND"
            if exc.code == 429 or exc.code in (500, 502, 503, 504):
                time.sleep(2**attempt)
                continue
            return None, None, f"HTTP_{exc.code}"
        except (urllib.error.URLError, TimeoutError, socket.timeout):
            time.sleep(2**attempt)
            continue
        except Exception:
            return None, None, "RDAP_ERROR"

    return None, None, "RDAP_FAILED"


def raw_whois(server, query):
    try:
        with socket.create_connection((server, 43), timeout=WHOIS_TIMEOUT) as sock:
            sock.settimeout(WHOIS_TIMEOUT)
            sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))

            chunks = []
            total_size = 0
            while True:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    break

                if not data:
                    break

                chunks.append(data)
                total_size += len(data)
                if total_size > 2_000_000:
                    break

            return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception:
        return None


def get_whois_server(tld):
    with whois_lock:
        if tld in whois_server_cache:
            return whois_server_cache[tld]

    response = raw_whois("whois.iana.org", tld)
    server = None

    if response:
        match = re.search(r"(?im)^whois:\s*(\S+)", response)
        if match:
            server = match.group(1).strip()

    with whois_lock:
        whois_server_cache[tld] = server

    return server


def extract_registrar_from_whois(text):
    if not text:
        return None

    patterns = [
        r"(?im)^Registrar:\s*(.+?)\s*$",
        r"(?im)^Sponsoring Registrar:\s*(.+?)\s*$",
        r"(?im)^Registrar Name:\s*(.+?)\s*$",
        r"(?im)^registrar-name:\s*(.+?)\s*$",
        r"(?im)^registrar_name:\s*(.+?)\s*$",
    ]

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            registrar = re.sub(r"\s+", " ", match.group(1).strip())
            if registrar:
                return registrar

    return None


def extract_abuse_email_from_whois(text):
    if not text:
        return None

    patterns = [
        r"(?im)^Registrar Abuse Contact Email:\s*(\S+@\S+)\s*$",
        r"(?im)^Registrar Abuse Email:\s*(\S+@\S+)\s*$",
        r"(?im)^Abuse Contact Email:\s*(\S+@\S+)\s*$",
        r"(?im)^Abuse Email:\s*(\S+@\S+)\s*$",
        r"(?im)^abuse-mailbox:\s*(\S+@\S+)\s*$",
        r"(?im)^abuse-email:\s*(\S+@\S+)\s*$",
    ]

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1).strip().rstrip(".,;)")

    for line in text.splitlines():
        if "abuse" not in line.lower():
            continue
        match = re.search(
            r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
            line,
            re.IGNORECASE,
        )
        if match:
            return match.group(0)

    return None


def whois_query(domain):
    labels = domain.split(".")
    if len(labels) < 2:
        return None, None

    tld = labels[-1]
    whois_server = get_whois_server(tld)
    if not whois_server:
        return None, None

    response = raw_whois(whois_server, domain)
    if not response:
        return None, None

    return extract_registrar_from_whois(response), extract_abuse_email_from_whois(response)


def find_registrar(hostname):
    if not hostname:
        return None, None, None

    candidates = generate_domain_candidates(hostname)

    with cache_lock:
        for candidate in candidates:
            cached = registrar_cache.get(candidate)
            if cached:
                return cached["registrar"], cached["abuse_email"], cached["source"]

    for candidate in candidates:
        registrar, abuse_email, _status = rdap_query(candidate)
        if registrar:
            source = "RDAP"
            if not abuse_email:
                _whois_registrar, whois_email = whois_query(candidate)
                if whois_email:
                    abuse_email = whois_email
                    source = "RDAP + WHOIS email"

            with cache_lock:
                registrar_cache[candidate] = {
                    "registrar": registrar,
                    "abuse_email": abuse_email,
                    "source": source,
                }
            return registrar, abuse_email, source

    for candidate in candidates:
        registrar, abuse_email = whois_query(candidate)
        if registrar:
            with cache_lock:
                registrar_cache[candidate] = {
                    "registrar": registrar,
                    "abuse_email": abuse_email,
                    "source": "WHOIS",
                }
            return registrar, abuse_email, "WHOIS"

    return None, None, None


def normalize_registrar_name(registrar):
    if not registrar:
        return "Unknown"

    registrar = registrar.strip()
    if registrar.lower() == "unknown":
        return "Unknown"

    key = re.sub(r"[^a-z0-9]", "", registrar.lower())
    mappings = [
        ("cloudflare", "Cloudflare"),
        ("namecheap", "Namecheap"),
        ("namesilo", "NameSilo"),
        ("spaceship", "Spaceship"),
        ("godaddy", "GoDaddy"),
        ("dynadot", "Dynadot"),
        ("gandi", "Gandi"),
        ("dnspod", "DNSPod"),
        ("namecom", "Name.com"),
    ]
    for needle, display in mappings:
        if needle in key:
            return display

    return re.sub(r"\s+", " ", registrar)


def process_url(url):
    hostname = get_hostname(url)
    if not hostname:
        return url, "Unknown", None, "INVALID URL"

    registrar, abuse_email, source = find_registrar(hostname)
    if registrar:
        return url, normalize_registrar_name(registrar), abuse_email, source

    return url, "Unknown", None, "RDAP + WHOIS failed"


def check_url_batch(raw_text):
    urls = clean_urls(raw_text)
    if not urls:
        raise ValueError("Không có URL hợp lệ để kiểm tra.")
    if len(urls) > MAX_URLS:
        raise ValueError(f"Tối đa {MAX_URLS} URL mỗi lần kiểm tra.")
    if not load_rdap_bootstrap():
        raise RuntimeError(
            "Không tải được IANA RDAP bootstrap. Hãy kiểm tra kết nối Internet của server."
        )

    grouped = {}
    source_stats = defaultdict(int)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_url, url): url for url in urls}
        for future in as_completed(futures):
            original_url = futures[future]
            try:
                url, registrar, abuse_email, source = future.result()
            except Exception:
                url, registrar, abuse_email, source = original_url, "Unknown", None, "ERROR"

            if registrar not in grouped:
                grouped[registrar] = {"email": abuse_email, "urls": []}
            elif not grouped[registrar]["email"] and abuse_email:
                grouped[registrar]["email"] = abuse_email

            grouped[registrar]["urls"].append(url)
            source_stats[source] += 1

    registrar_names = sorted(
        [name for name in grouped if name != "Unknown"], key=str.lower
    )
    if "Unknown" in grouped:
        registrar_names.append("Unknown")

    result_groups = []
    for registrar in registrar_names:
        result_groups.append(
            {
                "registrar": registrar,
                "abuse_email": grouped[registrar]["email"] or "Unknown",
                "urls": grouped[registrar]["urls"],
                "count": len(grouped[registrar]["urls"]),
            }
        )

    return {
        "total": len(urls),
        "groups": result_groups,
        "source_stats": dict(sorted(source_stats.items())),
    }


class RegistrarRequestHandler(BaseHTTPRequestHandler):
    server_version = "RegistrarChecker/1.0"

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def send_bytes(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_bytes(status, body, "application/json; charset=utf-8")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/":
            try:
                body = INDEX_FILE.read_bytes()
                self.send_bytes(200, body, "text/html; charset=utf-8")
            except OSError:
                self.send_bytes(500, b"Missing index.html", "text/plain; charset=utf-8")
            return

        if path.startswith("/static/"):
            relative = path[len("/static/"):]
            safe_path = (STATIC_DIR / relative).resolve()
            try:
                safe_path.relative_to(STATIC_DIR.resolve())
            except ValueError:
                self.send_bytes(403, b"Forbidden", "text/plain; charset=utf-8")
                return

            if not safe_path.is_file():
                self.send_bytes(404, b"Not found", "text/plain; charset=utf-8")
                return

            content_type = mimetypes.guess_type(str(safe_path))[0] or "application/octet-stream"
            if content_type.startswith("text/") or content_type in ("application/javascript", "application/json"):
                content_type += "; charset=utf-8"

            self.send_bytes(200, safe_path.read_bytes(), content_type)
            return

        self.send_bytes(404, b"Not found", "text/plain; charset=utf-8")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/check":
            self.send_json(404, {"error": "Not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0

        if content_length <= 0 or content_length > 10_000_000:
            self.send_json(400, {"error": "Request body không hợp lệ."})
            return

        try:
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
            raw_text = str(payload.get("urls", ""))
        except Exception:
            self.send_json(400, {"error": "JSON không hợp lệ."})
            return

        try:
            result = check_url_batch(raw_text)
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return
        except RuntimeError as exc:
            self.send_json(503, {"error": str(exc)})
            return
        except Exception:
            self.send_json(500, {"error": "Có lỗi không mong muốn khi xử lý URL."})
            return

        self.send_json(200, result)


def main():
    server = ThreadingHTTPServer((HOST, PORT), RegistrarRequestHandler)
    print("Registrar & Abuse Email Checker")
    print(f"Open: http://127.0.0.1:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
