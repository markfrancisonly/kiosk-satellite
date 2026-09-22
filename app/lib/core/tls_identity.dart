import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' show sha256;
import 'package:flutter/services.dart';

import '../managers/settings/definitions.dart' as defs;
import '../managers/settings/settings_manager.dart';
import 'event_bus.dart';
import 'events.dart';
import 'logging.dart';

/// What the kiosk's servers present over TLS.
class TlsMaterial {
  TlsMaterial(this.certificate, this.privateKey, this.notAfter)
    : fingerprint = sha256
          .convert(
            base64Decode(
              certificate.replaceAll(RegExp(r'-----[A-Z ]+-----|\s'), ''),
            ),
          )
          .bytes
          .map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase())
          .join(':');

  /// PEM text: the certificate and its PKCS#8 private key.
  final String certificate;
  final String privateKey;
  final DateTime notAfter;

  /// SHA-256 of the certificate as colon-separated hex, the way browsers
  /// show it.
  final String fingerprint;

  /// The context a dart:io server serves with. Made per call: a
  /// SecurityContext belongs to one server.
  SecurityContext securityContext() => SecurityContext()
    ..useCertificateChainBytes(utf8.encode(certificate))
    ..usePrivateKeyBytes(utf8.encode(privateKey));

  Map<String, Object?> toJson() => {
    'fingerprint': fingerprint,
    'notAfter': notAfter.toUtc().toIso8601String(),
    'certificate': certificate,
  };
}

/// The kiosk's TLS identity, one for both servers that can encrypt: the
/// remote admin (Use HTTPS) and the camera stream (Encrypt the stream).
///
/// A self-signed certificate the platform makes on first use (TlsBridge.kt)
/// and this keeps with the app's internal state. One instance, handed to
/// the serving managers by the composition root, so the two never disagree
/// about the certificate; [renew] replaces it and announces
/// [TlsIdentityChanged], which is what the servers restart on.
class TlsIdentity {
  TlsIdentity(this._settings, this._bus, this._log);

  final SettingsManager _settings;
  final EventBus _bus;
  final Logger _log;

  static const _channel = MethodChannel('kiosk_satellite/tls');
  static const _key = 'tls_identity';

  /// How long a certificate lasts: the most Apple platforms will trust.
  static const validity = Duration(days: 825);

  TlsMaterial? _cached;
  Future<TlsMaterial>? _loading;

  /// The material last loaded, without loading: what the servers present.
  TlsMaterial? get current => _cached;

  /// The certificate, made on first use. Overlapping loads share one.
  Future<TlsMaterial> load() async =>
      _cached ??
      await (_loading ??= _load().whenComplete(() => _loading = null));

  Future<TlsMaterial> _load() async {
    var raw = _settings.internal(_key);
    if (raw.isEmpty) {
      raw = await _generate();
      await _settings.setInternal(_key, raw);
    }
    final stored = jsonDecode(raw) as Map;
    return _cached = TlsMaterial(
      '${stored['certificate']}',
      '${stored['privateKey']}',
      DateTime.fromMillisecondsSinceEpoch(
        (stored['notAfter'] as num).toInt(),
        isUtc: true,
      ),
    );
  }

  /// A new certificate, for a kiosk renamed, moved or near the end of the
  /// old one. Whatever serves with it hears [TlsIdentityChanged].
  Future<TlsMaterial> renew() async {
    // A first load under way must not answer for the new certificate.
    try {
      await _loading;
    } catch (_) {}
    _cached = null;
    await _settings.setInternal(_key, '');
    final material = await load();
    _bus.publish(const TlsIdentityChanged());
    return material;
  }

  Future<String> _generate() async {
    final hostname = defs.effectiveHostname(
      _settings.get(defs.deviceHostname),
      _settings.get(defs.deviceName),
    );
    final label = hostname.isEmpty ? 'kiosk-satellite' : hostname;
    final made = await _channel.invokeMethod<Map>('generate', {
      'hostnames': ['$label.local', label],
      'days': validity.inDays,
    });
    _log.info('tls', 'made a self-signed certificate for $label.local');
    return jsonEncode({
      'certificate': made?['certificate'],
      'privateKey': made?['privateKey'],
      'notAfter': made?['notAfter'],
    });
  }
}
