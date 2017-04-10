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
import org.spongycastle.openpgp.PGPKeyRingGenerator;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPSecretKeyRing;
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
import org.spongycastle.openpgp.PGPEncryptedDataGenerator;
import java.lang.System;
import org.spongycastle.openpgp.PGPException;

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

        // String publicKeyString = publicKeyOutputStream.toString("UTF-8");
        // encrypt("some plain text", publicKeyString);

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


//   public void encrypt(String data, String armoredPublicKey) throws Exception {
//       // Provider[] prov = Security.getProviders();
//       // for(int i = 0; i < prov.length; i++) {
//       //   System.out.println(prov[i].getName());
//       // }
//       byte[] dataByteArray = data.getBytes(Charset.forName("UTF-8"));
//       PGPPublicKey key = readArmoredPublicKey(armoredPublicKey);

//       ByteArrayOutputStream compressedDataStream = new ByteArrayOutputStream();
//       PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(
//         PGPCompressedDataGenerator.ZIP
//       );

//       OutputStream outStream = compressedDataGenerator.open(compressedDataStream);
//       outStream.write(dataByteArray);
//       compressedDataGenerator.close();
//       outStream.close();

//       PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
//         PGPEncryptedDataGenerator.AES_256,
//         new SecureRandom(),
//         "BC"
//       );

//       encryptedDataGenerator.addMethod(key);

//       byte[] compressedData = compressedDataStream.toByteArray();
//       ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//       ArmoredOutputStream armoredOutputStream  = new ArmoredOutputStream(outputStream);
// System.out.println("VM_006");
//       OutputStream outDataStream = encryptedDataGenerator.open(armoredOutputStream, compressedData.length);
// System.out.println("VM_007");
//       outDataStream.write(compressedData);
//       encryptedDataGenerator.close();
//       armoredOutputStream.close();
//       String result = outputStream.toString("UTF-8");
//       System.out.println("FINDME_001");
//       System.out.println(result);
//   }

  @ReactMethod
  public void decrypt(String armoredEncryptedData, String armoredPrivateKey, Promise promise) {
    try {
      
    } catch (Exception e) {
      promise.reject(e.getMessage());
    }
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

//   private static PGPPublicKey readArmoredPublicKey(String in)
//                      throws Exception {
//               byte[] byteArrayPublicKeyString = in.getBytes(Charset.forName("UTF-8"));
//               ByteArrayInputStream publicKeyInputStream = new ByteArrayInputStream(byteArrayPublicKeyString);
//               ArmoredInputStream armoredPubInputStream = new ArmoredInputStream(publicKeyInputStream);

//               PGPPublicKeyRing pkRing = null;
//               PGPPublicKeyRingCollection pkCol = new PGPPublicKeyRingCollection(armoredPubInputStream);
//               System.out.println("key ring size=" + pkCol.size());
//               Iterator it = pkCol.getKeyRings();
//               while (it.hasNext()) {
//                       pkRing = (PGPPublicKeyRing) it.next();
//                       Iterator pkIt = pkRing.getPublicKeys();
//                       while (pkIt.hasNext()) {
//                               PGPPublicKey key = (PGPPublicKey) pkIt.next();
//                               System.out.println("Encryption key = " + key.isEncryptionKey() + ", Master key = " + 
//                                                  key.isMasterKey());
//                               if (key.isEncryptionKey())
//                                       return key;
//                       }
//               }
//               return null;
//       }
}
