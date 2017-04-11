package com.github.orhan.openpgp;

import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.Arguments;

import com.facebook.react.bridge.ReactContextBaseJavaModule;

import java.security.SecureRandom;

import android.util.Base64;

import org.apache.commons.io.IOUtils;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Provider;
import java.util.Date;
import java.util.Iterator;
import java.io.OutputStream;
import java.io.InputStream;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.bcpg.ArmoredInputStream;
import org.spongycastle.bcpg.sig.Features;
import org.spongycastle.bcpg.sig.KeyFlags;
import org.spongycastle.crypto.generators.RSAKeyPairGenerator;
import org.spongycastle.crypto.params.RSAKeyGenerationParameters;
import org.spongycastle.openpgp.PGPEncryptedData;
import org.spongycastle.openpgp.PGPKeyPair;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPPublicKeyRingCollection;
// import org.spongycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.spongycastle.openpgp.PGPKeyRingGenerator;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPSecretKeyRing;
import org.spongycastle.openpgp.PGPSecretKey;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.spongycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.spongycastle.openpgp.operator.PGPDigestCalculator;
import org.spongycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.spongycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.spongycastle.openpgp.PGPPrivateKey;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPCompressedDataGenerator;
import org.spongycastle.openpgp.PGPCompressedData;
import org.spongycastle.openpgp.PGPEncryptedDataGenerator;
import java.lang.System;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPUtil;
import org.spongycastle.bcpg.CompressionAlgorithmTags;
import org.spongycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder; 
import org.spongycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.spongycastle.crypto.util.PrivateKeyFactory;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.engines.RSAEngine;
import org.spongycastle.crypto.AsymmetricBlockCipher;
import org.spongycastle.openpgp.PGPObjectFactory;
import org.spongycastle.openpgp.PGPEncryptedDataList;
import org.spongycastle.openpgp.PGPPublicKeyEncryptedData;
import org.spongycastle.openpgp.PGPSecretKeyRingCollection;
import org.spongycastle.openpgp.PGPLiteralData;
import org.spongycastle.openpgp.PGPOnePassSignatureList;
import org.spongycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class RNOpenPGPModule extends ReactContextBaseJavaModule {

  public RNOpenPGPModule(ReactApplicationContext reactContext) {
    super(reactContext);
    Security.addProvider(new BouncyCastleProvider());
  }

  @Override
  public String getName() {
    return "RNOpenPGP";
  }
  @ReactMethod
  public void randomBytes(int size, Callback success) {
    SecureRandom sr = new SecureRandom();
    byte[] output = new byte[size];
    sr.nextBytes(output);
    String string = Base64.encodeToString(output, Base64.DEFAULT);
    success.invoke(null, string);
  }

  static {
    Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
  }

  @ReactMethod
  public void generateKeyPair(String userId, int numBits, String passphrase, Promise promise) {
    try {
        WritableMap resultMap = Arguments.createMap();
        PGPKeyRingGenerator keyGenerator = generateKeyRingGenerator(userId, numBits, passphrase.toCharArray());

        // public key
        PGPPublicKeyRing publicKeyRing              = keyGenerator.generatePublicKeyRing();
        ByteArrayOutputStream publicKeyOutputStream = new ByteArrayOutputStream();
        ArmoredOutputStream armoredPubOutputStream  = new ArmoredOutputStream(publicKeyOutputStream);

        publicKeyRing.encode(armoredPubOutputStream);
        armoredPubOutputStream.close();
        resultMap.putString("publicKey", publicKeyOutputStream.toString("UTF-8"));

        // private key
        PGPSecretKeyRing secretKeyRing               = keyGenerator.generateSecretKeyRing();
        ByteArrayOutputStream privateKeyOutputStream = new ByteArrayOutputStream();
        ArmoredOutputStream armoredPrivOutputStream  = new ArmoredOutputStream(privateKeyOutputStream);

        secretKeyRing.encode(armoredPrivOutputStream);
        armoredPrivOutputStream.close();
        resultMap.putString("privateKey", privateKeyOutputStream.toString("UTF-8"));

        promise.resolve(resultMap);
    } catch(Exception e) {
        e.printStackTrace();
        promise.reject(e.getMessage());
    }
  }

  private String encrypt(String message, String armoredPublicKey) throws Exception {
    WritableMap resultMap = Arguments.createMap();

    PGPPublicKey key = readArmoredPublicKey(armoredPublicKey);
    byte[] bytes = compressString(message, CompressionAlgorithmTags.ZLIB);

    PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
      new JcePGPDataEncryptorBuilder(
        PGPEncryptedData.AES_256
      )
      .setWithIntegrityPacket(true)
      .setSecureRandom(new SecureRandom())
      .setProvider("SC")
    );

    encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(key).setProvider("SC"));

    ByteArrayOutputStream outputStream      = new ByteArrayOutputStream();
    ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream);

    OutputStream writeInMe = encryptedDataGenerator.open(armoredOutputStream, bytes.length);

    writeInMe.write(bytes);
    writeInMe.close();
    armoredOutputStream.close();

    resultMap.putString("encryptedData", outputStream.toString("UTF-8"));
    return outputStream.toString("UTF-8");
  }

  private final static PGPKeyRingGenerator generateKeyRingGenerator(String userId, int numBits, char[] passphrase)
      throws Exception
  {
    RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();

    keyPairGenerator.init(
      new RSAKeyGenerationParameters(
        BigInteger.valueOf(0x10001),
        new SecureRandom(),
        numBits,
        12
      )
    );

    PGPKeyPair rsaKeyPairSign = new BcPGPKeyPair(
      PGPPublicKey.RSA_SIGN,
      keyPairGenerator.generateKeyPair(),
      new Date()
    );

    PGPKeyPair rsaKeyPairEncrypt = new BcPGPKeyPair(
      PGPPublicKey.RSA_ENCRYPT,
      keyPairGenerator.generateKeyPair(),
      new Date()
    );

    PGPSignatureSubpacketGenerator signHashGenerator = new PGPSignatureSubpacketGenerator();

    signHashGenerator.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);

    signHashGenerator.setPreferredSymmetricAlgorithms(
      false,
      new int[] {
        SymmetricKeyAlgorithmTags.AES_256,
        SymmetricKeyAlgorithmTags.AES_192,
        SymmetricKeyAlgorithmTags.AES_128
      }
    );

    signHashGenerator.setPreferredHashAlgorithms(
      false,
      new int[] {
        HashAlgorithmTags.SHA256,
        HashAlgorithmTags.SHA1,
        HashAlgorithmTags.SHA384,
        HashAlgorithmTags.SHA512,
        HashAlgorithmTags.SHA224,
      }
    );

    signHashGenerator.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

    PGPSignatureSubpacketGenerator encryptHashGenerator = new PGPSignatureSubpacketGenerator();

    encryptHashGenerator.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

    PGPDigestCalculator sha1DigestCalculator   = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
    PGPDigestCalculator sha256DigestCalculator = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

    PBESecretKeyEncryptor secretKeyEncryptor = (
      new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256DigestCalculator)
    )
    .build(passphrase);

    PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
      PGPSignature.NO_CERTIFICATION,
      rsaKeyPairSign,
      userId,
      sha1DigestCalculator,
      signHashGenerator.generate(),
      null,
      new BcPGPContentSignerBuilder(rsaKeyPairSign.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
      secretKeyEncryptor
    );

    keyRingGen.addSubKey(rsaKeyPairEncrypt, encryptHashGenerator.generate(), null);

    return keyRingGen;
  }

  private static PGPPublicKey readArmoredPublicKey(String in) throws Exception {
    byte[] byteArrayPublicKeyString = in.getBytes(Charset.forName("UTF-8"));
    ByteArrayInputStream publicKeyInputStream = new ByteArrayInputStream(byteArrayPublicKeyString);
    ArmoredInputStream armoredPubInputStream = new ArmoredInputStream(publicKeyInputStream);

    PGPPublicKeyRing pkRing = null;
    PGPPublicKeyRingCollection pkCol = new PGPPublicKeyRingCollection(armoredPubInputStream);
    System.out.println("key ring size=" + pkCol.size());
    Iterator it = pkCol.getKeyRings();
    while (it.hasNext()) {
      pkRing = (PGPPublicKeyRing) it.next();
      Iterator pkIt = pkRing.getPublicKeys();
      while (pkIt.hasNext()) {
              PGPPublicKey key = (PGPPublicKey) pkIt.next();
              if (key.isEncryptionKey()) return key;
      }
    }
    return null;
  }

  private static PGPSecretKey getSecretKeyFromArmoredString(String privateKeyIn) throws Exception {
    byte[] byteArrayPrivateKeyString = privateKeyIn.getBytes(Charset.forName("UTF-8"));
    ByteArrayInputStream privateKeyInputStream = new ByteArrayInputStream(byteArrayPrivateKeyString);
    PGPSecretKeyRingCollection secretKeyRingCollection = new PGPSecretKeyRingCollection(
      PGPUtil.getDecoderStream(privateKeyInputStream)
    );

    Iterator<PGPSecretKeyRing> iter = secretKeyRingCollection.getKeyRings();

    while (iter.hasNext()) {
      PGPSecretKeyRing keyRing = iter.next();
      
      Iterator<PGPSecretKey> secKeyIter = keyRing.getSecretKeys();
      while(secKeyIter.hasNext()) {
        PGPSecretKey tmpSecKey = secKeyIter.next();
        if (tmpSecKey.isMasterKey()) return tmpSecKey;
      }
    }

    return null;
  }

  private static byte[] compressString(String data, int algorithm) throws Exception {
      byte[] dataByteArray = data.getBytes(Charset.forName("UTF-8"));

      ByteArrayOutputStream resultOutStream              = new ByteArrayOutputStream(); 
      PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(algorithm);

      OutputStream outStream = compressedDataGenerator.open(resultOutStream);
      outStream.write(dataByteArray);
      compressedDataGenerator.close(); 
      
      byte[] result = resultOutStream.toByteArray();
      resultOutStream.close();

      return result;
  }
}
