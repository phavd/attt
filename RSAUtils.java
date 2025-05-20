package com.elcom.util.miscellaneous.crypt;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class RSAUtils {

//-------------------------------------------------------------------------------------------------------------------------
  private static final String RSA_CIPHER_INSTANCE  = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"; // "RSA" = "RSA/ECB/PKCS1Padding" 
  private static final OAEPParameterSpec OAEP_SHA256_MGF1_SPEC = new OAEPParameterSpec( // OAEPParameterSpec immutable and thread-safe
      "SHA-256",                    // Hash function
      "MGF1",                       // Mask generation function
      MGF1ParameterSpec.SHA256,     // MGF1 with SHA-256
      PSource.PSpecified.DEFAULT    // Default label (empty)
  );

  private static final String SIGNATURE_INSTANCE_PATTERN  = "%swithRSA"; // "SHA256withRSA", "SHA384withRSA", "SHA512withRSA"

//-------------------------------------------------------------------------------------------------------------------------
  public static RSAPrivateKey loadPrivateKey(String key) throws Exception {
    byte[] b = Base64.getDecoder().decode(key);
    
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(b);
    
    KeyFactory factory = KeyFactory.getInstance("RSA");
    return (RSAPrivateKey)factory.generatePrivate(spec);
  }

//-------------------------------------------------------------------------------------------------------------------------
  public static RSAPublicKey loadPublicKey(String key) throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
    RSAPublicKey publicKey = (RSAPublicKey)keyFactory.generatePublic(publicKeySpec);
    return publicKey;
  }

//-------------------------------------------------------------------------------------------------------------------------
  // Tạo cặp khóa RSA
  public static KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySize);
    return keyGen.generateKeyPair();
  }

//-------------------------------------------------------------------------------------------------------------------------
  public static String genKey(Key key) throws UnsupportedEncodingException {
    byte[] bKeyEncoded = key.getEncoded();
    byte[] b = DERtoString(bKeyEncoded);
    String rsaKey = new String(b);
    return rsaKey;
  }

//-------------------------------------------------------------------------------------------------------------------------
  private static byte[] DERtoString(byte[] bytes) throws UnsupportedEncodingException {
    ByteArrayOutputStream pemStream = new ByteArrayOutputStream();
    PrintWriter writer = new PrintWriter(pemStream);
    
    byte[] stringBytes = Base64.getEncoder().encode(bytes);
    String encoded = new String(stringBytes);
    encoded = encoded.replace("\r", "");
    encoded = encoded.replace("\n", "");
    
    int i = 0;
    while ((i + 1) * 64 <= encoded.length()) {
      writer.print(encoded.substring(i * 64, (i + 1) * 64));
      i++;
    }
    if (encoded.length() % 64 != 0) {
      writer.print(encoded.substring(i * 64));
    }
    writer.flush();
    return pemStream.toByteArray();
  }

//-------------------------------------------------------------------------------------------------------------------------
  // Mã hóa RSA: Hàm cũ
  public static String encryptRSA_OLD(String data, PublicKey publicKey) throws Exception {
    Cipher cipher = Cipher.getInstance(RSA_CIPHER_INSTANCE);
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
  }
  // Mã hóa RSA: Hàm mới
  public static String encryptRSA(String data, PublicKey publicKey) throws Exception {
    Cipher cipher = Cipher.getInstance(RSA_CIPHER_INSTANCE);
    cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_SHA256_MGF1_SPEC);
    byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(encryptedBytes);
  }

//-------------------------------------------------------------------------------------------------------------------------
  // Giải mã RSA: Hàm cũ
  public static String decryptRSA_OLD(String encryptedData, PrivateKey privateKey) throws Exception {
    Cipher cipher = Cipher.getInstance(RSA_CIPHER_INSTANCE);
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedData)), StandardCharsets.UTF_8);
  }
  // Giải mã RSA: Hàm mới
  public static String decryptRSA(String encryptedData, PrivateKey privateKey) throws Exception {
    Cipher cipher = Cipher.getInstance(RSA_CIPHER_INSTANCE);
    cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_SHA256_MGF1_SPEC);
    byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
    return new String(decryptedBytes, StandardCharsets.UTF_8);
  }


//-------------------------------------------------------------------------------------------------------------------------
  // Ký số bằng RSA. Chú ý shaName phải có dạng shortname SHA256 hoặc SHA384 hoặc SHA512
  public static String signData(String data, String shaName, PrivateKey privateKey) throws Exception {
    String signatureInstance = getSignatureInstance(shaName);
    Signature signature = Signature.getInstance(signatureInstance);
    signature.initSign(privateKey);
    signature.update(data.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(signature.sign());
  }

//-------------------------------------------------------------------------------------------------------------------------
  // Xác thực chữ ký số. Chú ý shaName phải có dạng shortname SHA256 hoặc SHA384 hoặc SHA512
  public static boolean verifySignature(String data, String shaName, String signedData, PublicKey publicKey) throws Exception {
    String signatureInstance = getSignatureInstance(shaName);
    Signature signature = Signature.getInstance(signatureInstance);
    signature.initVerify(publicKey);
    signature.update(data.getBytes(StandardCharsets.UTF_8));
    return signature.verify(Base64.getDecoder().decode(signedData));
  }

//-------------------------------------------------------------------------------------------------------------------------
  private static String getSignatureInstance(String shaName) {
    return String.format(SIGNATURE_INSTANCE_PATTERN, shaName);
  }

//-------------------------------------------------------------------------------------------------------------------------
  public static void main(String[] args) throws Throwable {
    /**
     * Giả sử cần viết một SERVER để cho CLIENT login bằng password đã được mã hóa
     * SERVER cần cấp cho CLIENT hai thông tin sau: password và publicKey của mình
     */
    // Đây là cặp RSA2048
    String serverPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnoDamtgroPE5y+lfqQl5ZskU2T4SPSU2mMHvcIayb1cW4Mz3BtMvWe1zVLPsF0DGMYn0p9temBK7l2PZ0NyJXk0KvBXgXwOqMrq8HDExz/Qxw4qXWN0TG/ztjMAJ+yknu8KbgSTwdsPS4+Y3Kq/P7/BKZil2ASVAAUp9nEbTSruSR2pKYi0Qx7m3WmZ48Rb3zkqoLpGAh3CkyFWgIfZv3mjWxfsZgGh5kSpt0nqCEMmOsjaUiMjmOflwPPhg/QEz7CcxBNxLUQt3hKXtdK7bGgC2Lx2A4kxvFvg+iQ9IzBzadLWdMpWSjJfXtaHN4BrlSNr/9iHcR8+9KEee/7nilwIDAQAB";
    String serverPrivateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCegNqa2Cug8TnL6V+pCXlmyRTZPhI9JTaYwe9whrJvVxbgzPcG0y9Z7XNUs+wXQMYxifSn216YEruXY9nQ3IleTQq8FeBfA6oyurwcMTHP9DHDipdY3RMb/O2MwAn7KSe7wpuBJPB2w9Lj5jcqr8/v8EpmKXYBJUABSn2cRtNKu5JHakpiLRDHubdaZnjxFvfOSqgukYCHcKTIVaAh9m/eaNbF+xmAaHmRKm3SeoIQyY6yNpSIyOY5+XA8+GD9ATPsJzEE3EtRC3eEpe10rtsaALYvHYDiTG8W+D6JD0jMHNp0tZ0ylZKMl9e1oc3gGuVI2v/2IdxHz70oR57/ueKXAgMBAAECggEAcqaH+ct1u4Php6LWhCILQ5Md1oo0jTAWzuYxOTblaO4Y6WC5KqGltamxa8p9ctByzDCa3LQsN1oNgVNDofV0E9csdaJpWrD+8pTqLoZTHrXnLSdZlHjNMsiAV/gtABTj3cfFzeOXYIEDUcAblW/4u/kXB9Djv65fHs/wDhOZEIt6y+F2j5QIT3DR6Uk/L4q8w/o78LljFGfptUs6HhGSuGs2WNVRlxiW+QbrAxSWsvLF7RfWnbwvHgt569C2FVRq+/1mH3q8fOTatTkes/aD+2Rn2Ae/9X8CqxtK+FUbsh1rfoGuhya+1Mf9PdCvVoJbY71sZjDbpUtmGaVIwzzsaQKBgQDaIGNoY+i4PZ888mjsuhvKpuSV2hkb318gl+ql8TZOh9wEfdDY3SeGkwSKrwfkzV1z1NqvSZMm0sLiayJTronaELGgtB+WdhmAvZxD21bz/YgKcGN8/bPoz7W6rInS0twOJes1N4pwX2tkhm4rVp7qqnENMkodR3er1yLXFCTgVQKBgQC6Bj7uCoAz/kX/PzpxrdCKIGZkAmPGqAqdPAdguU2zFgywvDJ4LAD+TZIHDOBw3WRxUCB6VEWoXUde4QCJVvwyMKbiQoIXkaETToVQHxR5qhNExpCKiWKlJUw2rAKfclDa7p8iMv6Hg+GjyxYfIC+dP167Lpw1fktb0aQgxKRzOwKBgGnRBoiQ10fx1PsrGg2lZ3ATMJclu8KSxUI5kIK6Fr9YFzsykgtylgcp8S0aJjkwC2Ly4rfgeHuACTzv/jIcXRGlwZYVa7GBT3PuCA2/LVqmJsXxqcHsDcgmY6HQq/fThR9z87vYWteS4rVcpbtuhR+QWdGuENhNYFfDwUoXoqAVAoGABs/zvgPkbgMBzTcjjMYwvN4y4ba0sLG2sctg+cnPbp+AF3jM4Fm8L5PnpRpzna593yhwCArOAjxoQLE8s8rbsXrWobKN0Q8kNvDJMQXyWgJAcmRTJr+hPSsAf4ANGIm3LE1Qxo/Xgl7yBG2LgdhL5hZMAc7TKaJWYCZtPEX3P8ECgYEArpkdSQT45NYNYrtWUxh2Du9I8tvnkK9jqZEti+QRmI16XZVKXqDV/1HAYcDmlVD03tgeTarjuDnwG7ptx7vIVNYBcI1eobInHbm8CZmGNfcF+wvqGmLrKMQV4L1hLup6uJGCAhEylwzkfVYVbf1qCZ1lIqibi5WEDAHn4n+Z8+s=";

    // STEP 1: CLIENT: Mã hóa password(đã được SERVER cấp offline) bằng PublicKey của SERVER(đã được SERVER cấp offline) 
    String password = "its@123";
    System.out.println("Password trước khi mã hóa: " + password);
    String passwordEncrypted = encryptRSA(password, loadPublicKey(serverPublicKey));

    // STEP 2: SERVER: Giải mã mật khẩu của CLIENT bằng PrivateKey của mình
    String passwordDecrypted = decryptRSA(passwordEncrypted, loadPrivateKey(serverPrivateKey));
    System.out.println("Password sau khi giải mã: " + passwordDecrypted);

    // STEP 1: CLIENT: Tạo chữ ký số bằng chuỗi tổng username + password
    // Đây là cặp RSA2048
    String clientPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnoDamtgroPE5y+lfqQl5ZskU2T4SPSU2mMHvcIayb1cW4Mz3BtMvWe1zVLPsF0DGMYn0p9temBK7l2PZ0NyJXk0KvBXgXwOqMrq8HDExz/Qxw4qXWN0TG/ztjMAJ+yknu8KbgSTwdsPS4+Y3Kq/P7/BKZil2ASVAAUp9nEbTSruSR2pKYi0Qx7m3WmZ48Rb3zkqoLpGAh3CkyFWgIfZv3mjWxfsZgGh5kSpt0nqCEMmOsjaUiMjmOflwPPhg/QEz7CcxBNxLUQt3hKXtdK7bGgC2Lx2A4kxvFvg+iQ9IzBzadLWdMpWSjJfXtaHN4BrlSNr/9iHcR8+9KEee/7nilwIDAQAB";
    String clientPrivateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCegNqa2Cug8TnL6V+pCXlmyRTZPhI9JTaYwe9whrJvVxbgzPcG0y9Z7XNUs+wXQMYxifSn216YEruXY9nQ3IleTQq8FeBfA6oyurwcMTHP9DHDipdY3RMb/O2MwAn7KSe7wpuBJPB2w9Lj5jcqr8/v8EpmKXYBJUABSn2cRtNKu5JHakpiLRDHubdaZnjxFvfOSqgukYCHcKTIVaAh9m/eaNbF+xmAaHmRKm3SeoIQyY6yNpSIyOY5+XA8+GD9ATPsJzEE3EtRC3eEpe10rtsaALYvHYDiTG8W+D6JD0jMHNp0tZ0ylZKMl9e1oc3gGuVI2v/2IdxHz70oR57/ueKXAgMBAAECggEAcqaH+ct1u4Php6LWhCILQ5Md1oo0jTAWzuYxOTblaO4Y6WC5KqGltamxa8p9ctByzDCa3LQsN1oNgVNDofV0E9csdaJpWrD+8pTqLoZTHrXnLSdZlHjNMsiAV/gtABTj3cfFzeOXYIEDUcAblW/4u/kXB9Djv65fHs/wDhOZEIt6y+F2j5QIT3DR6Uk/L4q8w/o78LljFGfptUs6HhGSuGs2WNVRlxiW+QbrAxSWsvLF7RfWnbwvHgt569C2FVRq+/1mH3q8fOTatTkes/aD+2Rn2Ae/9X8CqxtK+FUbsh1rfoGuhya+1Mf9PdCvVoJbY71sZjDbpUtmGaVIwzzsaQKBgQDaIGNoY+i4PZ888mjsuhvKpuSV2hkb318gl+ql8TZOh9wEfdDY3SeGkwSKrwfkzV1z1NqvSZMm0sLiayJTronaELGgtB+WdhmAvZxD21bz/YgKcGN8/bPoz7W6rInS0twOJes1N4pwX2tkhm4rVp7qqnENMkodR3er1yLXFCTgVQKBgQC6Bj7uCoAz/kX/PzpxrdCKIGZkAmPGqAqdPAdguU2zFgywvDJ4LAD+TZIHDOBw3WRxUCB6VEWoXUde4QCJVvwyMKbiQoIXkaETToVQHxR5qhNExpCKiWKlJUw2rAKfclDa7p8iMv6Hg+GjyxYfIC+dP167Lpw1fktb0aQgxKRzOwKBgGnRBoiQ10fx1PsrGg2lZ3ATMJclu8KSxUI5kIK6Fr9YFzsykgtylgcp8S0aJjkwC2Ly4rfgeHuACTzv/jIcXRGlwZYVa7GBT3PuCA2/LVqmJsXxqcHsDcgmY6HQq/fThR9z87vYWteS4rVcpbtuhR+QWdGuENhNYFfDwUoXoqAVAoGABs/zvgPkbgMBzTcjjMYwvN4y4ba0sLG2sctg+cnPbp+AF3jM4Fm8L5PnpRpzna593yhwCArOAjxoQLE8s8rbsXrWobKN0Q8kNvDJMQXyWgJAcmRTJr+hPSsAf4ANGIm3LE1Qxo/Xgl7yBG2LgdhL5hZMAc7TKaJWYCZtPEX3P8ECgYEArpkdSQT45NYNYrtWUxh2Du9I8tvnkK9jqZEti+QRmI16XZVKXqDV/1HAYcDmlVD03tgeTarjuDnwG7ptx7vIVNYBcI1eobInHbm8CZmGNfcF+wvqGmLrKMQV4L1hLup6uJGCAhEylwzkfVYVbf1qCZ1lIqibi5WEDAHn4n+Z8+s=";
    String username = "its";
    String signature = signData(username + password, "SHA256", loadPrivateKey(clientPrivateKey)); // SHA256, SHA384, SHA512

    // STEP 2: SERVER: Verify chữ ký số
    String verifyResult = String.valueOf( verifySignature (username + password, "SHA256", signature, loadPublicKey(clientPublicKey)) );
    System.out.println("Kết quả kiểm tra chữ ký số: " + verifyResult);
  }
}
