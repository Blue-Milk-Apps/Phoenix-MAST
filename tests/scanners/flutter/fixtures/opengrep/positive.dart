import 'dart:convert';
import 'dart:io';

void insecureExamples(dynamic prefs, dynamic hive, dynamic database, dynamic webView, dynamic channel) {
  final endpoint = Uri.parse('http://api.example.com/session');
  HttpClient().badCertificateCallback = (certificate, host, port) => true;
  webView.onReceivedServerTrustAuthRequest((request) => ServerTrustAuthResponseAction.PROCEED);

  prefs.setString('auth_token', 'secret-value');
  hive.put('user_password', 'password-value');
  print('session token: $endpoint');

  md5.convert(utf8.encode('value'));
  final cipher = 'AES/ECB/PKCS7Padding';
  database.rawQuery('SELECT * FROM users WHERE name = $endpoint');

  channel.setMethodCallHandler((call) async {
    if (call.method == 'deleteAccount') {
      return true;
    }
  });
}
