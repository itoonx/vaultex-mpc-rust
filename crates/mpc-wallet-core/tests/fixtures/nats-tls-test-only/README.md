# NATS mTLS test fixtures (throwaway, test only)

Throwaway test material for the NATS mTLS PEM loader tests in
`src/transport/nats.rs`. It is used nowhere else. These keys protect nothing:
never use them, or certificates issued by this CA, outside these tests.

Generated once with the system `openssl` CLI (LibreSSL 3.3.6). The test CA's
private key was discarded right after it signed the two client certificates,
so nothing more can be issued under this CA.

| File | Content |
|---|---|
| `ca.pem` | Self-signed test CA certificate (P-256), CN `vaultex-nats-test-only-ca` |
| `client-ec.pem` | Client certificate (`clientAuth`) for the P-256 client key, issued by the test CA |
| `client-ec-key-pkcs8.pem` | The P-256 client key, PKCS#8 (`BEGIN PRIVATE KEY`) |
| `client-ec-key-sec1.pem` | The same P-256 key, SEC1 (`BEGIN EC PRIVATE KEY`) |
| `client-rsa.pem` | Client certificate (`clientAuth`) for the RSA-2048 client key, issued by the test CA |
| `client-rsa-key-pkcs1.pem` | The RSA-2048 client key, PKCS#1 (`BEGIN RSA PRIVATE KEY`) |

All certificates are valid for 100 years from 2026-10-17.

## Regenerating

Run in an empty scratch directory, then copy the six files above here and
delete the rest (the CA key, CSRs and config files).

```sh
cat > ca.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = vaultex-nats-test-only-ca
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[v3_client]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
for kind in ec rsa; do
  printf '[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = vaultex-nats-test-only-client-%s\n' "$kind" > "req-$kind.cnf"
done

openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem
openssl req -x509 -new -key ca-key.pem -sha256 -days 36500 -config ca.cnf -extensions v3_ca -out ca.pem

openssl ecparam -name prime256v1 -genkey -noout -out client-ec-key-sec1.pem
openssl pkcs8 -topk8 -nocrypt -in client-ec-key-sec1.pem -out client-ec-key-pkcs8.pem
openssl req -new -key client-ec-key-sec1.pem -config req-ec.cnf -out client-ec.csr
openssl x509 -req -in client-ec.csr -CA ca.pem -CAkey ca-key.pem -set_serial "0x$(openssl rand -hex 16)" \
  -days 36500 -sha256 -extfile ca.cnf -extensions v3_client -out client-ec.pem

openssl genrsa -out client-rsa-key-pkcs1.pem 2048   # LibreSSL writes PKCS#1; OpenSSL 3 needs -traditional
openssl req -new -key client-rsa-key-pkcs1.pem -config req-rsa.cnf -out client-rsa.csr
openssl x509 -req -in client-rsa.csr -CA ca.pem -CAkey ca-key.pem -set_serial "0x$(openssl rand -hex 16)" \
  -days 36500 -sha256 -extfile ca.cnf -extensions v3_client -out client-rsa.pem

openssl verify -CAfile ca.pem client-ec.pem client-rsa.pem
rm ca-key.pem ./*.csr ./*.cnf
```
