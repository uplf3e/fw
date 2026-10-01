import functools
import json
import secrets

from flask import (
    Flask,
    redirect,
    render_template,
    request,
    make_response,
    session,
    url_for,
)

from requests.exceptions import RequestException

from . import db
from .config import SECRET_KEY
from .proxy import parse_headers, perform_request, do_request

_CLIENT_PASSTHROUGH = {"user-agent", "accept", "accept-language"}


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapper


def register(app: Flask) -> None:
    @app.route("/")
    def index():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=("GET", "POST"))
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = db.verify_user(username, password)
            if user:
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return redirect(url_for("dashboard"))
            error = "Неверный логин или пароль"
        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/dashboard", methods=("GET", "POST"))
    @login_required
    def dashboard():
        created = None
        error = None
        if request.method == "POST":
            url = request.form.get("url", "").strip()
            method = request.form.get("method", "GET").upper()
            headers_raw = request.form.get("headers", "")
            try:
                headers = parse_headers(headers_raw)
            except Exception as exc:
                error = f"Ошибка разбора заголовков: {exc}"
                headers = {}

            if not url:
                error = "URL обязателен"
            elif not error:
                result = perform_request(method, url, headers)
                token = secrets.token_urlsafe(16)
                db.insert_request(
                    token,
                    session["user_id"],
                    method,
                    url,
                    json.dumps(headers, ensure_ascii=False),
                    result,
                )
                return redirect(
                    url_for("dashboard", created=url_for("proxy", token=token, _external=True))
                )

        items = db.list_requests_by_owner(session["user_id"])
        created = request.args.get("created")
        return render_template(
            "dashboard.html", items=items, created=created, error=error
        )

    @app.route("/r/<token>", defaults={"subpath": ""})
    @app.route("/r/<token>/<path:subpath>")
    def proxy(token, subpath):
        row = db.get_request_by_token(token)
        if not row:
            return "Not found", 404
        try:
            headers = json.loads(row["req_headers"]) if row["req_headers"] else {}
        except (json.JSONDecodeError, ValueError):
            headers = {}

        lower_keys = {k.lower() for k in headers}
        for h in _CLIENT_PASSTHROUGH:
            if h not in lower_keys and h in request.headers:
                headers[h] = request.headers[h]

        target = row["url"]
        if subpath:
            sep = "" if target.endswith("/") else "/"
            target += sep + subpath
        if request.query_string:
            target += "?" + request.query_string.decode()

        method = request.method
        body = request.get_data() if method != "GET" else None
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if client_ip and "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()
        req_path = request.full_path
        try:
            upstream = do_request(method, target, headers, body)
        except RequestException as exc:
            db.record_access(token, client_ip, request.user_agent.string, req_path, None)
            return f"Request failed: {exc}", 502

        resp = make_response(upstream.content)
        resp.status_code = upstream.status_code
        for k, v in upstream.headers.items():
            lk = k.lower()
            if lk in ("transfer-encoding", "connection", "content-length", "content-encoding"):
                continue
            resp.headers[k] = v
        db.record_access(token, client_ip, request.user_agent.string, req_path, upstream.status_code)
        return resp

    @app.route("/view/<token>")
    def view(token):
        row = db.get_request_by_token(token)
        if not row:
            return render_template("view.html", not_found=True), 404
        try:
            headers = json.loads(row["req_headers"]) if row["req_headers"] else {}
        except (json.JSONDecodeError, ValueError):
            headers = {}
        result = perform_request(row["method"], row["url"], headers)
        live = dict(row)
        live["status_code"] = result["status_code"]
        live["resp_headers"] = result["resp_headers"]
        live["resp_body"] = result["resp_body"]
        live["error"] = result["error"]
        access_log = db.get_access_log(token)
        return render_template("view.html", row=live, live=True, access_log=access_log)
