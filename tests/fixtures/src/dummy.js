function badCode() {
  eval("console.log('hello')");

  const f = new Function('return 1');

  console.log('secret data');

  const apiKey = 'AKIA1234567890ABCDEF';

  const url = 'http://insecure-api.com/data';

  AsyncStorage.setItem('authToken', 'super-secret-token');

  const webview = <WebView source={{ uri: url }} />;
}

function safeCode() {
  // Loopback URLs must NOT be flagged by the insecure URL detector
  const localUrl = 'http://localhost:3000/api';
  const loopbackUrl = 'http://127.0.0.1:8080/api';
}
