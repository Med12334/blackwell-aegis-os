package main

import (
"crypto/sha256"
"encoding/base64"
"strings"
)

// Layer 18 & 19: OAuth 2.1 PKCE (S256) + FIDO2/WebAuthn Hardware Key Authenticator
func VerifyOAuth21PkceAndFido2(codeVerifier string, expectedCodeChallenge string, fido2UserVerified bool, fido2HardwareBacked bool) bool {
if !fido2UserVerified || !fido2HardwareBacked || len(codeVerifier) < 43 {
return false
}
digest := sha256.Sum256([]byte(codeVerifier))
computedChallenge := base64.RawURLEncoding.EncodeToString(digest[:])
return computedChallenge == expectedCodeChallenge
}

// Layer 20 & 21: Active Directory / Entra ID Cross-Realm Trust & SCIMv2 Provisioning Guard
type CrossRealmPrincipal struct {
UserPrincipalName string
SourceRealm       string
TargetRealm       string
KerberosEncType   string
Scimv2Synced      bool
}

func AuthorizeCrossRealmAdTrust(p CrossRealmPrincipal) string {
if !p.Scimv2Synced {
return "DENY_SCIMV2_PROVISIONING_INCOMPLETE"
}
// Require AES256-CTS-HMAC-SHA1-96 for Kerberos cross-realm TGTs (forbid legacy RC4/DES)
if p.KerberosEncType != "AES256-CTS-HMAC-SHA1-96" {
return "DENY_WEAK_KERBEROS_ENCTYPE"
}
if p.SourceRealm == "CORP.NVIDIA.COM" && p.TargetRealm == "HPC.BLACKWELL.PREPROD" {
return "ALLOW_CROSS_REALM_KERBEROS_TRUST"
}
return "DENY_UNTRUSTED_REALM_BOUNDARY"
}

// Layer 22 & 23: FreeIPA / RHEL IdM / SSSD Host-Based Access Control (HBAC) & PKI mTLS Validator
type FreeIpaHbacRequest struct {
UnixUid           string
SssdGroup         string
TargetClusterHost string
ServiceName       string
ClientCertSan     string
CertRevokedOscp   bool
}

func EvaluateFreeIpaHbacPolicy(req FreeIpaHbacRequest) bool {
if req.CertRevokedOscp || !strings.HasSuffix(req.ClientCertSan, ".hpc.blackwell.preprod") {
return false
}
if strings.HasPrefix(req.TargetClusterHost, "gb200-preprod-") {
return req.SssdGroup == "ipa_gpu_cluster_admins" || req.SssdGroup == "ipa_preprod_sec_ir"
}
return false
}
