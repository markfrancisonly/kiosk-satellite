import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kiosk_satellite/core/command_registry.dart';
import 'package:kiosk_satellite/core/event_bus.dart';
import 'package:kiosk_satellite/core/events.dart';
import 'package:kiosk_satellite/core/logging.dart';
import 'package:kiosk_satellite/core/tls_identity.dart';
import 'package:kiosk_satellite/managers/settings/definitions.dart' as defs;
import 'package:kiosk_satellite/managers/settings/settings_manager.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'tls_fixture.dart';

/// The one certificate both servers present: made by the platform once
/// and kept, remade on demand.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  final calls = <MethodCall>[];
  late EventBus bus;
  late Logger log;
  late SettingsManager settings;
  late TlsIdentity tls;

  setUp(() async {
    calls.clear();
    messenger.setMockMethodCallHandler(
      const MethodChannel('kiosk_satellite/tls'),
      (call) async {
        calls.add(call);
        return generatedPair(calls.length);
      },
    );
    SharedPreferences.setMockInitialValues({
      'ks.device.name': 'Kitchen Tablet',
    });
    bus = EventBus();
    log = Logger();
    settings = SettingsManager(bus, CommandRegistry(log), log);
    await settings.init();
    tls = TlsIdentity(settings, bus, log);
  });

  test('makes a certificate for the kiosk once and keeps it', () async {
    final material = await tls.load();
    expect(material.certificate, testCertificatePem);
    expect(material.privateKey, testPrivateKeyPem);
    expect(material.fingerprint, testCertificateFingerprint);
    expect(material.notAfter, DateTime.utc(2046, 9, 17));
    expect(tls.current, same(material));
    final hostname = defs.effectiveHostname('', 'Kitchen Tablet');
    expect(calls.single.arguments, {
      'hostnames': ['$hostname.local', hostname],
      'days': TlsIdentity.validity.inDays,
    });
    expect(await tls.load(), same(material));
    // A fresh app run reads the stored one back instead of making another.
    final again = await TlsIdentity(settings, bus, log).load();
    expect(again.fingerprint, testCertificateFingerprint);
    expect(calls, hasLength(1));
    expect(material.securityContext(), isNotNull);
    expect(material.toJson(), {
      'fingerprint': testCertificateFingerprint,
      'notAfter': '2046-09-17T00:00:00.000Z',
      'certificate': testCertificatePem,
    });
  });

  test('overlapping first loads make one certificate', () async {
    final both = await Future.wait([tls.load(), tls.load()]);
    expect(both.first, same(both.last));
    expect(calls, hasLength(1));
  });

  test('renew makes a new certificate, keeps it and says so', () async {
    await tls.load();
    final events = <TlsIdentityChanged>[];
    bus.on<TlsIdentityChanged>().listen(events.add);
    final renewed = await tls.renew();
    await Future<void>.delayed(Duration.zero);
    expect(renewed.fingerprint, testRenewedCertificateFingerprint);
    expect(tls.current, same(renewed));
    expect(events, hasLength(1));
    final nextRun = await TlsIdentity(settings, bus, log).load();
    expect(nextRun.fingerprint, testRenewedCertificateFingerprint);
  });

  test(
    'a renewal during the first load hands back the new certificate',
    () async {
      final first = tls.load();
      final renewed = await tls.renew();
      expect((await first).fingerprint, testCertificateFingerprint);
      expect(renewed.fingerprint, testRenewedCertificateFingerprint);
      expect(tls.current, same(renewed));
    },
  );
}
