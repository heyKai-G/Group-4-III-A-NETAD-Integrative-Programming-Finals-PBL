"""Command-line admin tasks.

  python manage.py init-db        create the database tables
  python manage.py reset-admin    set a new admin password and re-enroll 2FA
  python manage.py purge          delete alerts older than RETENTION_DAYS now
  python manage.py show-config    print the saved network settings
"""
import getpass
import sys
from datetime import timedelta

from app import create_app
from app.extensions import db
from app.models import Alert, LoginAttempt, NetworkConfig, User, utcnow
from app import security as sec


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    app = create_app()
    with app.app_context():
        if cmd == "init-db":
            db.create_all()
            print("Database tables are ready.")
        elif cmd == "reset-admin":
            db.create_all()
            user = User.query.order_by(User.id).first()
            if not user:
                print("No admin exists yet. Open the dashboard and create one on the setup page.")
                return 1
            print(f"Resetting the password for '{user.username}'.")
            while True:
                pw = getpass.getpass("New password: ")
                if pw != getpass.getpass("Repeat password: "):
                    print("Passwords do not match.")
                    continue
                problems = []
                with app.test_request_context():
                    problems = sec.password_problems(pw, user.username)
                if problems:
                    print("\n".join(problems))
                    continue
                break
            user.password_hash = sec.hash_password(pw)
            user.totp_secret_enc = sec.encrypt_secret(sec.new_totp_secret())
            user.totp_enabled = False
            user.last_totp_step = 0
            LoginAttempt.query.filter_by(username=user.username.lower()).delete()
            db.session.commit()
            print("Done. Log in with the new password; you will be asked to set up 2FA again.")
        elif cmd == "purge":
            days = app.config["RETENTION_DAYS"]
            n = Alert.query.filter(Alert.ts < utcnow() - timedelta(days=days)).delete()
            db.session.commit()
            print(f"Deleted {n} alert(s) older than {days} days.")
        elif cmd == "show-config":
            c = NetworkConfig.query.first()
            print("Not configured yet." if not c else
                  {k: getattr(c, k) for k in ("network_name", "subnet_cidr", "gateway_ip",
                                              "iface_name", "iface_device", "sensitivity",
                                              "dhcp_servers")})
        else:
            print(__doc__)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
