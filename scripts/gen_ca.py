"""Create Root CA (RSA + self-signed X.509) using cryptography.

This script now accepts CLI options to match README usage:
  --name  : Common Name for the Root CA (default: 'SecureChat Root CA')
  --out   : Output prefix (default writes to `certs/ca-private.key` and `certs/ca-cert.crt`)
  --days  : Validity in days (default 3650 / 10 years)
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import argparse
import os


def create_root_ca(name: str, out_prefix: str | None, days: int):
    # Create certs directory if it doesn't exist
    os.makedirs('certs', exist_ok=True)

    # Generate private key for Root CA
    print("Generating Root CA private key...")
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate self-signed certificate for Root CA
    print("Creating Root CA certificate...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "CS"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=days)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_private_key, hashes.SHA256())

    # Determine output paths
    if out_prefix:
        key_path = f"{out_prefix}-private.key"
        cert_path = f"{out_prefix}-cert.crt"
    else:
        key_path = "certs/ca-private.key"
        cert_path = "certs/ca-cert.crt"

    # Save private key
    with open(key_path, "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save certificate
    with open(cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print("✅ Root CA created successfully!")
    print(f"   - Private key: {key_path}")
    print(f"   - Certificate: {cert_path}")


def main():
    parser = argparse.ArgumentParser(description="Create a self-signed Root CA certificate")
    parser.add_argument('--name', default='SecureChat Root CA', help='Common Name for the Root CA')
    parser.add_argument('--out', help='Output prefix (e.g. certs/ca)')
    parser.add_argument('--days', type=int, default=3650, help='Validity in days (default 3650)')
    args = parser.parse_args()

    create_root_ca(args.name, args.out, args.days)


if __name__ == "__main__":
    main()