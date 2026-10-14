# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib, struct, urllib.request, sys
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils as asn1
from cryptography.hazmat.primitives import hashes

def load(b): return x509.load_pem_x509_certificate(b) if b[:10]==b"-----BEGIN" else x509.load_der_x509_certificate(b)
rep = open("report-vaultgenome.bin","rb").read()[:1184]
pub = open("x25519-pub.der","rb").read()
nonce = bytes.fromhex(open("vg-nonce.hex").read().strip())
report_data = rep[0x50:0x90]; measurement = rep[0x90:0xC0]; chip = rep[0x1A0:0x1E0]

# 1. binding: REPORT_DATA == SHA-512(pub || nonce)
want = hashlib.sha512(pub + nonce).digest()
b_ok = report_data == want

# 2. report signature (ECDSA-P384) under VCEK
vcek = load(open("cert-VCEK.bin","rb").read())
r = int.from_bytes(rep[0x2A0:0x2A0+48],"little"); s = int.from_bytes(rep[0x2A0+72:0x2A0+120],"little")
try:
    vcek.public_key().verify(asn1.encode_dss_signature(r,s), rep[:0x2A0], ec.ECDSA(hashes.SHA384())); sig_ok=True
except Exception as e: sig_ok=False; print("sig err:",e)

# 3. VCEK chains to AMD ARK-Milan — fetch KDS chain OURSELVES (independent of the guest)
try:
    chainpem = urllib.request.urlopen("https://kdsintf.amd.com/vcek/v1/Milan/cert_chain", timeout=40).read()
    certs = x509.load_pem_x509_certificates(chainpem)  # [ASK, ARK]
    ask, ark = certs[0], certs[1]
    def rsapss_ok(child, parent):
        parent.public_key().verify(child.signature, child.tbs_certificate_bytes,
            padding.PSS(mgf=padding.MGF1(child.signature_hash_algorithm), salt_length=padding.PSS.DIGEST_LENGTH),
            child.signature_hash_algorithm); return True
    vcek_by_ask = rsapss_ok(vcek, ask)
    ask_by_ark  = rsapss_ok(ask, ark)
    ark_self    = rsapss_ok(ark, ark)
    chain_ok = vcek_by_ask and ask_by_ark and ark_self
    ark_subj = ark.subject.rfc4514_string()
except Exception as e:
    chain_ok=False; ark_subj=f"(fetch/verify err: {e})"

# 4. hwID (VCEK ext 1.3.6.1.4.1.3704.1.4) == CHIP_ID
hw = [e for e in vcek.extensions if e.oid.dotted_string=="1.3.6.1.4.1.3704.1.4"]
hwid_ok = bool(hw) and hw[0].value.value[-64:]==chip

flags = struct.unpack_from("<I",rep,0x48)[0]
print("=== Vault Genome — REAL SEV-SNP attestation verification ===")
print(f"report version         : {struct.unpack_from('<I',rep,0)[0]}")
print(f"signing key            : {'VCEK' if ((flags>>2)&7)==0 else 'VLEK/other'}")
print(f"debug mode             : {'YES (INSECURE)' if flags&1 else 'no (production)'}")
print(f"CHIP_ID                : {chip.hex()[:32]}… (zeroed={chip==bytes(64)})")
print(f"MEASUREMENT (48B SHA384): {measurement.hex()}")
print(f"pubkey (X25519 SPKI)   : {pub.hex()}")
print(f"nonce (challenger)     : {nonce.hex()}")
print("-"*60)
print(f"1. REPORT_DATA == SHA-512(pubkey || nonce)  : {'PASS' if b_ok else 'FAIL'}")
print(f"2. report ECDSA-P384 signature under VCEK   : {'PASS' if sig_ok else 'FAIL'}")
print(f"3. VCEK → ASK → ARK-Milan (fetched from KDS): {'PASS' if chain_ok else 'FAIL'}   [{ark_subj}]")
print(f"4. VCEK hwID == report CHIP_ID             : {'PASS' if hwid_ok else 'FAIL'}")
allok = b_ok and sig_ok and chain_ok and hwid_ok
print("="*60)
print("VERDICT:", "GENUINE SEV-SNP TEE, key bound to hardware ✅" if allok else "NOT FULLY VERIFIED ❌")
sys.exit(0 if allok else 1)
