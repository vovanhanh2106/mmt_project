"""Sinh chứng chỉ TLS tự ký cho phòng lab + in mã ghim SHA-256 để đưa cho agent (--pin)."""
import datetime, hashlib, ipaddress, os, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(out, exist_ok=True)
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
san = [x509.DNSName(host)]
try: san.append(x509.IPAddress(ipaddress.ip_address(host)))
except ValueError: pass
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC)).not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san), False).sign(key, hashes.SHA256()))
with open(os.path.join(out, "server.key"), "wb") as f:
    f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
os.chmod(os.path.join(out, "server.key"), 0o600)
with open(os.path.join(out, "server.crt"), "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
print("Đã tạo", out, "\nMã ghim SHA-256 (dùng cho agent --pin):", hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())
