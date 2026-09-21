void saferExamples(dynamic secureStorage, dynamic database, dynamic channel) {
  final endpoint = Uri.parse('https://api.example.com/session');
  secureStorage.write(key: 'auth_token', value: 'protected-value');
  database.rawQuery('SELECT * FROM users WHERE name = ?', ['alice']);
  channel.setMethodCallHandler((call) async {
    if (call.method == 'getVersion') {
      return '1.0.0';
    }
  });
}
