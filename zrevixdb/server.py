"""HTTP Server implementation and routing using Python http.server standard library."""

import json
import mimetypes
import os
import re
import urllib.parse
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


class Request:
    """Encapsulates parsed HTTP request data."""

    def __init__(
        self,
        method: str,
        path: str,
        query: Dict[str, list],
        headers: Dict[str, str],
        body: bytes,
        path_params: Optional[Dict[str, str]] = None,
    ):
        self.method = method.upper()
        self.path = path
        self.query = query
        self.headers = headers
        self.body = body
        self.path_params = path_params or {}
        self.user: Optional[Dict[str, Any]] = None
        self._cookies: Optional[Dict[str, str]] = None

    @property
    def cookies(self) -> Dict[str, str]:
        """Parsed dictionary of cookie key-value pairs."""
        if self._cookies is None:
            self._cookies = {}
            cookie_header = self.headers.get("cookie") or self.headers.get("Cookie")
            if cookie_header:
                simple_cookie = cookies.SimpleCookie()
                try:
                    simple_cookie.load(cookie_header)
                    for key, morsel in simple_cookie.items():
                        self._cookies[key] = morsel.value
                except Exception:
                    pass
        return self._cookies

    def json(self) -> Any:
        """Parse request body as JSON. Returns None for empty or invalid bodies."""
        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None


class Response:
    """Encapsulates HTTP response data."""

    def __init__(
        self,
        body: Any = b"",
        status: int = 200,
        content_type: str = "text/plain; charset=utf-8",
        headers: Optional[Dict[str, Union[str, List[str]]]] = None,
    ):
        self.status = status
        self.content_type = content_type
        self.headers: Dict[str, Union[str, List[str]]] = headers or {}
        if isinstance(body, str):
            self.body = body.encode("utf-8")
        elif isinstance(body, bytes):
            self.body = body
        else:
            self.body = b""

    def set_cookie(
        self,
        key: str,
        value: str,
        max_age: Optional[int] = None,
        path: str = "/",
        httponly: bool = True,
        samesite: str = "Lax",
        secure: bool = False,
    ):
        """Set an HTTP cookie via Set-Cookie header."""
        cookie = cookies.SimpleCookie()
        cookie[key] = value
        if max_age is not None:
            cookie[key]["max-age"] = str(max_age)
        if path:
            cookie[key]["path"] = path
        if httponly:
            cookie[key]["httponly"] = True
        if samesite:
            cookie[key]["samesite"] = samesite
        if secure:
            cookie[key]["secure"] = True

        cookie_str = cookie.output(header="").strip()
        set_cookie_headers = self.headers.get("Set-Cookie")
        if set_cookie_headers is None:
            self.headers["Set-Cookie"] = [cookie_str]
        elif isinstance(set_cookie_headers, list):
            set_cookie_headers.append(cookie_str)
        else:
            self.headers["Set-Cookie"] = [set_cookie_headers, cookie_str]

    def delete_cookie(self, key: str, path: str = "/"):
        """Delete an HTTP cookie by setting max-age to 0."""
        self.set_cookie(key=key, value="", max_age=0, path=path, httponly=True, samesite="Lax")

    @classmethod
    def json(cls, data: Any, status: int = 200) -> "Response":
        """Convenience method to create a JSON response."""
        body = json.dumps(data, indent=2).encode("utf-8")
        return cls(body=body, status=status, content_type="application/json; charset=utf-8")

    @classmethod
    def html(cls, html_str: str, status: int = 200) -> "Response":
        """Convenience method to create an HTML response."""
        return cls(body=html_str.encode("utf-8"), status=status, content_type="text/html; charset=utf-8")

    @classmethod
    def file(cls, filepath: str, content_type: Optional[str] = None) -> "Response":
        """Convenience method to create a file response."""
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return cls.json({"error": "File not found"}, status=404)
        if not content_type:
            content_type, _ = mimetypes.guess_type(filepath)
            content_type = content_type or "application/octet-stream"
        with open(filepath, "rb") as f:
            content = f.read()
        return cls(body=content, status=200, content_type=content_type)


class RouteEntry:
    """Represents a compiled route pattern and handler."""

    def __init__(self, raw_path: str, handler: Callable[[Request], Response]):
        self.raw_path = raw_path
        self.handler = handler
        # Convert :param or {param} to regex named group (?P<param>[^/]+)
        pattern = re.sub(r":([a-zA-Z_][a-zA-Z0-9_]*)", r"(?P<\1>[^/]+)", raw_path)
        pattern = re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", r"(?P<\1>[^/]+)", pattern)
        self.regex = re.compile(f"^{pattern}$")

    def match(self, path: str) -> Optional[Dict[str, str]]:
        m = self.regex.match(path)
        if m:
            return m.groupdict()
        return None


class Router:
    """Lightweight router supporting exact paths and parameterized routes."""

    def __init__(self):
        self.routes: Dict[str, Dict[str, Callable[[Request], Response]]] = {
            "GET": {},
            "POST": {},
            "PUT": {},
            "DELETE": {},
            "PATCH": {},
            "OPTIONS": {},
        }
        self.param_routes: Dict[str, List[RouteEntry]] = {
            "GET": [],
            "POST": [],
            "PUT": [],
            "DELETE": [],
            "PATCH": [],
            "OPTIONS": [],
        }

    def add_route(self, method: str, path: str, handler: Callable[[Request], Response]):
        """Register a route handler for a given method and path."""
        method_upper = method.upper()
        if method_upper not in self.routes:
            self.routes[method_upper] = {}
            self.param_routes[method_upper] = []

        if ":" in path or "{" in path:
            self.param_routes[method_upper].append(RouteEntry(path, handler))
        else:
            self.routes[method_upper][path] = handler

    def get(self, path: str):
        def decorator(fn: Callable[[Request], Response]):
            self.add_route("GET", path, fn)
            return fn
        return decorator

    def post(self, path: str):
        def decorator(fn: Callable[[Request], Response]):
            self.add_route("POST", path, fn)
            return fn
        return decorator

    def put(self, path: str):
        def decorator(fn: Callable[[Request], Response]):
            self.add_route("PUT", path, fn)
            return fn
        return decorator

    def delete(self, path: str):
        def decorator(fn: Callable[[Request], Response]):
            self.add_route("DELETE", path, fn)
            return fn
        return decorator

    def dispatch(self, req: Request) -> Response:
        """Find matching route handler and dispatch request."""
        # 1. Exact match
        handlers_for_method = self.routes.get(req.method, {})
        if req.path in handlers_for_method:
            return handlers_for_method[req.path](req)

        # 2. Parameterized match
        param_list = self.param_routes.get(req.method, [])
        for entry in param_list:
            matched_params = entry.match(req.path)
            if matched_params is not None:
                req.path_params = matched_params
                return entry.handler(req)

        return Response.json({"error": f"Route not found: {req.method} {req.path}"}, status=404)


def make_request_handler(router: Router, static_dir: str):
    """Factory creating a BaseHTTPRequestHandler class configured with router and static directory."""

    class ZRevixHTTPRequestHandler(BaseHTTPRequestHandler):
        server_version = "ZRevixDB/0.1.0"

        def _safe_join_static(self, rel_path: str) -> Optional[str]:
            """Resolve a path under static_dir, or None if it escapes the directory."""
            cleaned = os.path.normpath(rel_path.replace("\\", "/").lstrip("/"))
            if cleaned == ".." or cleaned.startswith(".." + os.sep):
                return None
            target_path = os.path.abspath(os.path.join(static_dir, cleaned))
            abs_static = os.path.abspath(static_dir)
            try:
                if os.path.commonpath([target_path, abs_static]) != abs_static:
                    return None
            except ValueError:
                return None
            return target_path

        def _serve_static(self, rel_path: str) -> bool:
            """Attempt to serve a static file. Returns True if handled, False otherwise."""
            target_path = self._safe_join_static(rel_path)
            if target_path is None:
                self._send_response(Response.json({"error": "Forbidden"}, status=403))
                return True

            if os.path.isfile(target_path):
                resp = Response.file(target_path)
                self._send_response(resp)
                return True
            return False

        def _send_response(self, resp: Response):
            """Send HTTP status, headers, and body back to client."""
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.content_type)
            self.send_header("Content-Length", str(len(resp.body)))
            origin = self.headers.get("Origin")
            if origin:
                # Echo a specific origin; '*' cannot be combined with credentials.
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, Cookie")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

            for k, v in resp.headers.items():
                if isinstance(v, list):
                    for item in v:
                        self.send_header(k, str(item))
                else:
                    self.send_header(k, str(v))

            self.end_headers()
            self.wfile.write(resp.body)

        def _handle_request(self, method: str):
            parsed_url = urllib.parse.urlparse(self.path)
            path = parsed_url.path
            query = urllib.parse.parse_qs(parsed_url.query)

            # Serve root as index.html
            if method == "GET" and path in ("/", "/index.html"):
                index_path = os.path.join(static_dir, "index.html")
                if os.path.isfile(index_path):
                    self._send_response(Response.file(index_path, content_type="text/html; charset=utf-8"))
                    return

            # Serve direct HTML files under static or root
            if method == "GET" and (path.endswith(".html") or "." not in path):
                clean_path = path.lstrip("/")
                candidate = self._safe_join_static(clean_path)
                html_candidate = self._safe_join_static(clean_path + ".html") if clean_path else None
                if candidate and os.path.isfile(candidate):
                    self._send_response(Response.file(candidate, content_type="text/html; charset=utf-8"))
                    return
                if html_candidate and os.path.isfile(html_candidate):
                    self._send_response(Response.file(html_candidate, content_type="text/html; charset=utf-8"))
                    return

            # Serve static files under /static/
            if method == "GET" and path.startswith("/static/"):
                sub_path = path[len("/static/"):]
                if self._serve_static(sub_path):
                    return

            # Read request body if present
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else b""

            headers_dict = {k: v for k, v in self.headers.items()}
            req = Request(
                method=method,
                path=path,
                query=query,
                headers=headers_dict,
                body=body,
            )

            try:
                resp = router.dispatch(req)
            except Exception as exc:
                resp = Response.json({"error": "Internal Server Error", "details": str(exc)}, status=500)

            self._send_response(resp)

        def do_GET(self):
            self._handle_request("GET")

        def do_POST(self):
            self._handle_request("POST")

        def do_PUT(self):
            self._handle_request("PUT")

        def do_DELETE(self):
            self._handle_request("DELETE")

        def do_OPTIONS(self):
            self._send_response(Response(body=b"", status=204))

        def log_message(self, format: str, *args: Any):
            """Custom log format."""
            print(f"[HTTP] {self.address_string()} - {format % args}")

    return ZRevixHTTPRequestHandler


def run_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    router: Optional[Router] = None,
    static_dir: Optional[str] = None,
) -> ThreadingHTTPServer:
    """Start and return a ThreadingHTTPServer instance."""
    if router is None:
        router = Router()
    if static_dir is None:
        static_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

    handler_cls = make_request_handler(router, static_dir)
    server = ThreadingHTTPServer((host, port), handler_cls)
    return server
