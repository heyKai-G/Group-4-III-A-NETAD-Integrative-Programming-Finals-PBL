import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))


@pytest.fixture()
def app(tmp_path):
    from app import create_app
    from app.extensions import db
    # Set TEST_DATABASE_URL (e.g. postgresql+pg8000://user:pw@localhost/db) to run the suite on PostgreSQL.
    uri = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path/'t.db'}"
    app = create_app({
        "TESTING": True, "SECRET_KEY": "k" * 40,
        "SQLALCHEMY_DATABASE_URI": uri,
        "SESSION_COOKIE_SECURE": False, "WTF_CSRF_ENABLED": False,
        "LOCAL_RULES_PATH": str(tmp_path / "local.rules"),
        "EVE_JSON_PATH": str(tmp_path / "eve.json"),
    })
    with app.app_context():
        db.drop_all()
        db.create_all()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()
