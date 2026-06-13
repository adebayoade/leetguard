function badCode() {
  eval("console.log('hello')");

  const f = new Function('return 1');

  console.log('secret data');

  const apiKey = 'AKIA1234567890ABCDEF';

  const url = 'http://insecure-api.com/data';
}
