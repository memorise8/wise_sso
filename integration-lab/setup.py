"""Generate local-only TLS, client secrets and disposable test-account credentials."""

import ipaddress
import json
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from argon2 import PasswordHasher
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

root = Path(__file__).resolve().parent / ".local"
root.mkdir(exist_ok=True, mode=0o700)
material = root / "material.json"
if material.exists():
    data = json.loads(material.read_text())
else:
    data = {
        "customer": secrets.token_urlsafe(32),
        "staff": secrets.token_urlsafe(32),
        "password": secrets.token_urlsafe(24),
    }
    material.write_text(json.dumps(data))
    material.chmod(0o600)
policies = []
hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
for kind, port in [("customer", 4445), ("staff", 4446)]:
    policies.append(
        {
            "clientId": f"lab-{kind}",
            "clientSecretHash": hasher.hash(data[kind]),
            "redirectUris": [f"https://localhost:{port}/callback"],
            "requiredRoles": [{"serviceKey": f"lab-{kind}", "name": "user"}],
            "groupsServiceKeys": [f"lab-{kind}"],
            "requirePkce": True,
            "allowedUserTypes": ["EMPLOYEE", "CUSTOMER", "UNCLASSIFIED"]
            if kind == "customer"
            else ["EMPLOYEE"],
        }
    )
text = "LAB_OIDC_CLIENTS_JSON='" + json.dumps(policies, separators=(",", ":")) + "'\n"
text += f"LAB_CUSTOMER_SECRET={data['customer']}\nLAB_STAFF_SECRET={data['staff']}\n"
(root / "compose.env").write_text(text)
(root / "compose.env").chmod(0o600)
fixtures = [
    {"email": f"{name}@wise-lab.invalid", "name": name, "password": data["password"]}
    for name in ["customer", "employee", "unapproved", "suspended"]
]
(root / "fixtures.json").write_text(json.dumps(fixtures))
(root / "fixtures.json").chmod(0o600)
# The existing app image runs as UID 10001; only local fixture data needs to be readable.
(root / "fixtures.json").chmod(0o644)
if not (root / "tls.crt").exists():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wise SSO Local Lab")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    (root / "tls.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (root / "tls.key").chmod(0o600)
    (root / "tls.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
print("Generated integration-lab/.local files. No existing .env files changed.")
print("Local fixture credentials: integration-lab/.local/fixtures.json (do not publish)")

# Separate local SMTP certificate: never replace the existing browser TLS material.
# Python's default SSL context trusts this certificate via SSL_CERT_FILE in the lab overlay.
if not (root / "smtp.crt").exists() or not (root / "smtp.key").exists():
    smtp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    smtp_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mailpit")])
    smtp_now = datetime.now(UTC)
    smtp_cert = (
        x509.CertificateBuilder()
        .subject_name(smtp_name)
        .issuer_name(smtp_name)
        .public_key(smtp_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(smtp_now - timedelta(minutes=5))
        .not_valid_after(smtp_now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("mailpit")]), critical=False)
        .sign(smtp_key, hashes.SHA256())
    )
    (root / "smtp.key").write_bytes(
        smtp_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (root / "smtp.key").chmod(0o600)
    (root / "smtp.crt").write_bytes(smtp_cert.public_bytes(serialization.Encoding.PEM))
    (root / "smtp.crt").chmod(0o644)
# Preserve normal public CA trust for provider HTTP clients sharing this process.
public_ca = Path("/etc/ssl/certs/ca-certificates.crt").read_bytes()
(root / "smtp-ca-bundle.crt").write_bytes(public_ca + b"\n" + (root / "smtp.crt").read_bytes())
(root / "smtp-ca-bundle.crt").chmod(0o644)
print("Local SMTP certificate ready. Mail is captured locally, never forwarded.")
