let RNOpenPGP = require('react-native').NativeModules.RNOpenPGP;

export default async function generateKeyPair({
    userId = '',
    numBits = 2048,
    passphrase = ''
}) {
  if (RNOpenPGP.generateKeyPair) {
    return await RNOpenPGP.generateKeyPair(userId, numBits, passphrase);
  }

  throw new Error('iOS implementation is not ready yet');
}