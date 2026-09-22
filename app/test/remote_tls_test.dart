import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kiosk_satellite/core/command_registry.dart';
import 'package:kiosk_satellite/core/event_bus.dart';
import 'package:kiosk_satellite/core/logging.dart';
import 'package:kiosk_satellite/managers/remote/remote_manager.dart';
import 'package:kiosk_satellite/managers/settings/definitions.dart' as defs;
import 'package:kiosk_satellite/managers/settings/settings_manager.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'tls_fixture.dart';

/// Use HTTPS: the admin server serves TLS on its port with the kiosk's
/// certificate, follows the switch and a renewal live, and says why when
/// it cannot.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() => HttpOverrides.global = null);
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  late EventBus bus;
  late Logger log;
  late SettingsManager settings;
  late CommandRegistry commands;
  late RemoteManager remote;
  late int port;
  var generated = 0;
  var platformFails = false;

  /// The subject of the certificate the last connection was shown.
  String? servedSubject;

  setUp(() async {
    generated = 0;
    platformFails = false;
    servedSubject = null;
    messenger.setMockMethodCallHandler(
      const MethodChannel('kiosk_satellite/tls'),
      (call) async {
        if (platformFails) {
          throw PlatformException(code: 'read_failed', message: 'no keys');
        }
        return generatedPair(++generated);
      },
    );
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    SharedPreferences.setMockInitialValues({
      'ks.browser.start_url': 'http://ha.local:8123/lovelace/0',
      'ks.remote.enabled': true,
      'ks.remote.password': 'secret',
      'ks.remote.port': port,
      'ks.remote.tls': true,
    });
    bus = EventBus();
    log = Logger();
    commands = CommandRegistry(log);
    settings = SettingsManager(bus, commands, log);
    await settings.init();
    remote = RemoteManager(bus, commands, log, settings);
    await remote.init();
  });

  tearDown(() => remote.dispose());

  Future<void> settle() async {
    for (var i = 0; i < 40; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
  }

  /// One request to the admin port: its status and body, or a null status
  /// when the connection never yields a response.
  Future<(int?, String)> call(
    String method,
    String path, {
    String scheme = 'https',
    String? token,
    Object? body,
  }) async {
    final client = HttpClient()
      ..badCertificateCallback = (cert, host, port) {
        servedSubject = cert.subject;
        return true;
      };
    try {
      final request = await client
          .openUrl(method, Uri.parse('$scheme://127.0.0.1:$port$path'))
          .timeout(const Duration(seconds: 3));
      if (token != null) request.headers.set('authorization', 'Bearer $token');
      if (body != null) request.write(jsonEncode(body));
      final response = await request.close().timeout(
        const Duration(seconds: 3),
      );
      return (response.statusCode, await utf8.decodeStream(response));
    } catch (_) {
      return (null, '');
    } finally {
      client.close(force: true);
    }
  }

  Future<int?> health(String scheme) async =>
      (await call('GET', '/api/health', scheme: scheme)).$1;

  test('serves https on its port with the kiosk certificate', () async {
    expect(remote.stoppedReason.value, isNull);
    expect(await health('https'), 200);
    expect(servedSubject, contains('kiosk-test.local'));
    expect(await health('http'), isNull, reason: 'plain text is refused');
    expect(generated, 1);
    // The certificate a browser can be told to trust, never its key.
    final info = await commands.execute('tlsCertificate', const {});
    expect(info.ok, isTrue);
    expect(info.data, {
      'fingerprint': testCertificateFingerprint,
      'notAfter': '2046-09-17T00:00:00.000Z',
      'certificate': testCertificatePem,
    });
  });

  test('the switch and a renewal move the server live', () async {
    await settings.set(defs.remoteTls, false);
    await settle();
    expect(await health('http'), 200);
    expect(await health('https'), isNull);
    await settings.set(defs.remoteTls, true);
    await settle();
    expect(await health('https'), 200);
    expect(servedSubject, contains('kiosk-test.local'));
    // A renewal restarts the server on the new certificate.
    final renewed = await commands.execute('renewTlsCertificate', const {});
    expect(renewed.ok, isTrue);
    expect(generated, 2);
    await settle();
    expect(await health('https'), 200);
    expect(servedSubject, contains('kiosk-renewed.local'));
    final info = await commands.execute('tlsCertificate', const {});
    expect(
      (info.data as Map)['fingerprint'],
      testRenewedCertificateFingerprint,
    );
    expect(remote.stoppedReason.value, isNull);
  });

  test('a renewal asked over the API is answered before the restart', () async {
    final (_, login) = await call(
      'POST',
      '/api/login',
      body: {'password': 'secret'},
    );
    final token = (jsonDecode(login) as Map)['token'] as String;
    final (status, body) = await call(
      'POST',
      '/api/commands/renewTlsCertificate',
      token: token,
    );
    expect(status, 200, reason: 'the reply must go out before the restart');
    final data = (jsonDecode(body) as Map)['data'] as Map;
    expect(data['fingerprint'], testRenewedCertificateFingerprint);
    await settle();
    expect(await health('https'), 200);
    expect(servedSubject, contains('kiosk-renewed.local'));
  });

  test('a certificate that cannot be had is said, not served around', () async {
    // A kiosk whose platform cannot make one, from the first start: a
    // certificate already loaded serves on regardless of the platform.
    await remote.dispose();
    platformFails = true;
    SharedPreferences.setMockInitialValues({
      'ks.browser.start_url': 'http://ha.local:8123/lovelace/0',
      'ks.remote.enabled': true,
      'ks.remote.password': 'secret',
      'ks.remote.port': port,
      'ks.remote.tls': true,
    });
    bus = EventBus();
    commands = CommandRegistry(log);
    settings = SettingsManager(bus, commands, log);
    await settings.init();
    remote = RemoteManager(bus, commands, log, settings);
    await remote.init();
    expect(await health('http'), isNull);
    expect(await health('https'), isNull);
    expect(remote.stoppedReason.value, contains('certificate'));
    // Back to plain http the moment the switch goes off.
    await settings.set(defs.remoteTls, false);
    await settle();
    expect(await health('http'), 200);
    expect(remote.stoppedReason.value, isNull);
  });
}
