"""Lab IDS - Flask application factory."""
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import Flask, redirect, render_template, request, url_for
from flask_login import current_user

from .config import Config
from .extensions import csrf, db, login_manager


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY is not set. Run setup.ps1 (it creates the .env file).")
    if not app.config.get("SQLALCHEMY_DATABASE_URI"):
        raise RuntimeError("DATABASE_URL is not set. Run setup.ps1 (it creates the .env file).")

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"
    login_manager.login_message = "Please log in."
    login_manager.login_message_category = "warning"

    from . import models  # noqa: F401  (register tables)
    from .auth import bp as auth_bp
    from .views import bp as main_bp
    from .api import bp as api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    try:
        tz = ZoneInfo(app.config["APP_TZ"])
    except ZoneInfoNotFoundError:
        tz = ZoneInfo("UTC")

    @app.template_filter("localtime")
    def localtime(value, fmt="%Y-%m-%d %H:%M:%S"):
        if not value:
            return ""
        return value.replace(tzinfo=ZoneInfo("UTC")).astimezone(tz).strftime(fmt)

    @app.context_processor
    def inject_globals():
        from .models import CATEGORIES
        return {"all_categories": CATEGORIES, "now_year": datetime.now().year}

    @app.before_request
    def gate():
        """First run -> create admin. Logged in but no network config -> wizard."""
        endpoint = request.endpoint or ""
        if endpoint == "static":
            return None
        from .models import NetworkConfig, User
        if User.query.count() == 0:
            if endpoint not in ("auth.setup", "auth.enroll_2fa"):
                return redirect(url_for("auth.setup"))
            return None
        if current_user.is_authenticated and not endpoint.startswith("auth."):
            if endpoint not in ("main.wizard",) and NetworkConfig.query.first() is None:
                return redirect(url_for("main.wizard"))
        return None

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; font-src 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("error.html", code=403, message="Forbidden."), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, message="Page not found."), 404

    @app.errorhandler(400)
    def bad_request(e):
        msg = getattr(e, "description", "Bad request.")
        return render_template("error.html", code=400, message=msg), 400

    @app.errorhandler(500)
    def server_error(_e):
        return render_template("error.html", code=500, message="Something went wrong."), 500

    return app
