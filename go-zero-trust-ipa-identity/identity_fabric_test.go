package main

import (
"crypto/sha256"
"encoding/base64"
"testing"
)

func TestLayer18OAuth21PkceAndFido2WebAuthn(t *testing.T) {
verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-blackwell-2026"
hash := sha256.Sum256([]byte(verifier))
challenge := base64.RawURLEncoding.EncodeToString(hash[:])

if !VerifyOAuth21PkceAndFido2(verifier, challenge, true, true) {
t.Fatal("Expected valid OAuth 2.1 S256 PKCE + FIDO2 hardware attestation to pass")
}
if VerifyOAuth21PkceAndFido2(verifier, challenge, true, false) {
t.Fatal("Expected non-hardware-backed authenticator to be rejected")
}
}

func TestLayer20AdEntraCrossRealmKerberosAndScimV2(t *testing.T) {
validPrincipal := CrossRealmPrincipal{
UserPrincipalName: "mkhelifi@CORP.NVIDIA.COM",
SourceRealm:       "CORP.NVIDIA.COM",
TargetRealm:       "HPC.BLACKWELL.PREPROD",
KerberosEncType:   "AES256-CTS-HMAC-SHA1-96",
Scimv2Synced:      true,
}
if AuthorizeCrossRealmAdTrust(validPrincipal) != "ALLOW_CROSS_REALM_KERBEROS_TRUST" {
t.Fatal("Expected AES256 Kerberos cross-realm trust with active SCIMv2 sync to succeed")
}
}

func TestLayer22FreeIpaSssdHbacAndPkiLifecycle(t *testing.T) {
hbac := FreeIpaHbacRequest{
UnixUid:           "mkhelifi",
SssdGroup:         "ipa_preprod_sec_ir",
TargetClusterHost: "gb200-preprod-node01",
ServiceName:       "sshd",
ClientCertSan:     "mkhelifi.hpc.blackwell.preprod",
CertRevokedOscp:   false,
}
if !EvaluateFreeIpaHbacPolicy(hbac) {
t.Fatal("Expected FreeIPA HBAC policy to grant SSH/Slurm access to authorized IR group")
}
}
