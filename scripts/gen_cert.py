"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).

Usage examples (README):
  python scripts/gen_cert.py --cn server.local --out certs/server
  python scripts/gen_cert.py --cn client.local --out certs/client
"""
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from datetime import datetime, timedelta
import argparse
import os


def issue_cert(cn: str, out_prefix: str, days: int = 365):
	# Ensure CA files exist
	ca_key_path = os.path.join('certs', 'ca-private.key')
	ca_cert_path = os.path.join('certs', 'ca-cert.crt')
	if not os.path.exists(ca_key_path) or not os.path.exists(ca_cert_path):
		raise FileNotFoundError("Root CA files not found. Run scripts/gen_ca.py first.")

	# Load CA private key
	with open(ca_key_path, 'rb') as f:
		ca_key_pem = f.read()
	ca_private_key = load_pem_private_key(ca_key_pem, password=None)

	# Load CA certificate
	with open(ca_cert_path, 'rb') as f:
		ca_cert = x509.load_pem_x509_certificate(f.read())

	# Create directory for output if needed
	out_dir = os.path.dirname(out_prefix)
	if out_dir:
		os.makedirs(out_dir, exist_ok=True)

	# Generate private key for entity
	print(f"Generating private key for {cn}...")
	priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

	# Build subject
	subject = x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
		x509.NameAttribute(NameOID.COMMON_NAME, cn),
	])

	# Build certificate
	print(f"Creating certificate for {cn} signed by Root CA...")
	cert_builder = x509.CertificateBuilder()
	cert_builder = cert_builder.subject_name(subject)
	cert_builder = cert_builder.issuer_name(ca_cert.subject)
	cert_builder = cert_builder.public_key(priv_key.public_key())
	cert_builder = cert_builder.serial_number(x509.random_serial_number())
	cert_builder = cert_builder.not_valid_before(datetime.utcnow() - timedelta(minutes=1))
	cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=days))
	# Add SAN with DNSName equal to CN
	cert_builder = cert_builder.add_extension(
		x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False
	)
	# Basic constraints: not a CA
	cert_builder = cert_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

	cert = cert_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())

	# Write private key and certificate
	key_path = f"{out_prefix}-private.key"
	cert_path = f"{out_prefix}-cert.crt"

	with open(key_path, 'wb') as f:
		f.write(priv_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption()
		))

	with open(cert_path, 'wb') as f:
		f.write(cert.public_bytes(serialization.Encoding.PEM))

	print("Certificate issued successfully!")
	print(f"   - Private key: {key_path}")
	print(f"   - Certificate: {cert_path}")


def main():
	parser = argparse.ArgumentParser(description="Issue certificate signed by local Root CA")
	parser.add_argument('--cn', required=True, help='Common Name (DNS) for the certificate')
	parser.add_argument('--out', required=True, help='Output prefix (e.g. certs/server)')
	parser.add_argument('--days', type=int, default=365, help='Validity days (default 365)')
	args = parser.parse_args()

	issue_cert(args.cn, args.out, args.days)


if __name__ == '__main__':
	main()
