package com.elcom.util.miscellaneous.crypt;

import javax.crypto.SecretKey;

public class AESCBCUtils extends AESUtils {
  private static final AESMode mode = AESMode.CBC;

//-------------------------------------------------------------------------------------------------------------------------
  // Mã hóa dữ liệu
  public static String encrypt(String plaintext, byte[] secretKey) throws Exception {
    byte[] iv = generateIV(mode);
    return AESUtils.encrypt(plaintext, secretKey, iv, mode);
  }
  public static String encrypt(String plaintext, SecretKey secretKey) throws Exception {
    byte[] iv = generateIV(mode);
    return AESUtils.encrypt(plaintext, secretKey, iv, mode);
  }

//-------------------------------------------------------------------------------------------------------------------------
  // Giải mã dữ liệu
  public static String decrypt(String encryptedData, byte[] secretKey) throws Exception {
    return AESUtils.decrypt(encryptedData, secretKey, mode);
  }
  public static String decrypt(String encryptedData, SecretKey secretKey) throws Exception {
    return AESUtils.decrypt(encryptedData, secretKey, mode);
  }
}
