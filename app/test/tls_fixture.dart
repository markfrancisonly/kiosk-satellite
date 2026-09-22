/// A throwaway EC P-256 key and self-signed certificate for the TLS tests
/// (CN kiosk-test.local, SAN localhost and 127.0.0.1, valid to 2046).
/// Made with openssl; nothing outside the test suite trusts it.
const testCertificatePem = '''
-----BEGIN CERTIFICATE-----
MIIBujCCAWCgAwIBAgIUFVINQdiNfULZb0sbfVV21ZzqxykwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQa2lvc2stdGVzdC5sb2NhbDAeFw0yNjA5MjIxMjIyMTNaFw00
NjA5MTcxMjIyMTNaMBsxGTAXBgNVBAMMEGtpb3NrLXRlc3QubG9jYWwwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAR9VyGyu1ogeXjKL7Ss66xrkEsWm/scwktX8aJm
f0bb3iTEzVb9s4Ueqrm9D6of1EYQ9U0vr8jWn5B3eTXcg13Bo4GBMH8wHQYDVR0O
BBYEFGitiXZ450ztji4fLGMZM/fUFnZVMB8GA1UdIwQYMBaAFGitiXZ450ztji4f
LGMZM/fUFnZVMA8GA1UdEwEB/wQFMAMBAf8wLAYDVR0RBCUwI4IQa2lvc2stdGVz
dC5sb2NhbIIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49BAMCA0gAMEUCIQC8reEO
bmT2I/NTn3HKFRZN4dqQyM/t45wsGMu3N+szCAIgdVknoQ/xPdjcmfDpEopejQY+
N7SbygzLfmClrX1DgUU=
-----END CERTIFICATE-----
''';

const testPrivateKeyPem = '''
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5YhJJT1fvMr5r8sa
8AhNmguEdjGSxDgazY+sp5024kKhRANCAAR9VyGyu1ogeXjKL7Ss66xrkEsWm/sc
wktX8aJmf0bb3iTEzVb9s4Ueqrm9D6of1EYQ9U0vr8jWn5B3eTXcg13B
-----END PRIVATE KEY-----
''';

/// A second pair, what a renewal makes (CN kiosk-renewed.local).
const testRenewedCertificatePem = '''
-----BEGIN CERTIFICATE-----
MIIBwzCCAWqgAwIBAgIUL3c9vqpU62M+2iXzRuDXT90a6kAwCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTa2lvc2stcmVuZXdlZC5sb2NhbDAeFw0yNjA5MjIxMzI1NDJa
Fw00NjA5MTcxMzI1NDJaMB4xHDAaBgNVBAMME2tpb3NrLXJlbmV3ZWQubG9jYWww
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATk1d4m6k/k9OcGdxAAgO/h7hT9thcg
HzZYIDTeNBig0lZCg1KEDifwsLU2AS/J5TyQ2L8ydTHL2fkgSbHa6T13o4GFMIGC
MB0GA1UdDgQWBBSJQ5pZJqSxEzY8g5NCjJ4jmZDxGDAfBgNVHSMEGDAWgBSJQ5pZ
JqSxEzY8g5NCjJ4jmZDxGDAPBgNVHRMBAf8EBTADAQH/MC8GA1UdEQQoMCaCE2tp
b3NrLXJlbmV3ZWQubG9jYWyCCWxvY2FsaG9zdIcEfwAAATAKBggqhkjOPQQDAgNH
ADBEAiBnAyzIpfHioOyb/J7rLPvu28+6x8oIgtTckI4txJatcwIgTQ75SW/YPHDC
o8iwB6fKbFjzEKHdwDqVOxV5P9GzwC4=
-----END CERTIFICATE-----
''';

const testRenewedPrivateKeyPem = '''
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9rOoVZoeal3lxVCw
qI/G8YfeYaiqxAZjcYQRViofGZChRANCAATk1d4m6k/k9OcGdxAAgO/h7hT9thcg
HzZYIDTeNBig0lZCg1KEDifwsLU2AS/J5TyQ2L8ydTHL2fkgSbHa6T13
-----END PRIVATE KEY-----
''';

/// Their SHA-256 fingerprints, as openssl reports them.
const testCertificateFingerprint =
    '64:DE:6A:35:58:EE:87:6F:D9:69:F2:F9:24:44:29:9B:'
    '12:9D:FA:1A:66:7B:21:A5:D3:36:67:3E:D8:58:B8:E0';
const testRenewedCertificateFingerprint =
    '4D:54:4E:6B:DC:54:5A:8F:D8:DA:BF:74:81:D4:C0:C1:'
    '01:74:0E:DB:60:F1:9D:86:12:40:94:0C:DD:F4:C4:44';

/// What the platform's generate call answers: the first pair on the first
/// call, the second on any later one, so a renewal is visible.
Map<String, Object> generatedPair(int call) => call == 1
    ? {
        'certificate': testCertificatePem,
        'privateKey': testPrivateKeyPem,
        'notAfter': DateTime.utc(2046, 9, 17).millisecondsSinceEpoch,
      }
    : {
        'certificate': testRenewedCertificatePem,
        'privateKey': testRenewedPrivateKeyPem,
        'notAfter': DateTime.utc(2046, 9, 18).millisecondsSinceEpoch,
      };
