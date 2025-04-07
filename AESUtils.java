package com.elcom.util.miscellaneous.crypt;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESUtils {
  private static final int GCM_IV_LENGTH    = 12; // IV cho GCM (12 byte)
  private static final int CBC_IV_LENGTH    = 16; // IV cho CBC (16 byte)
  private static final int GCM_TAG_LENGTH   = 16; // Authentication Tag 16 byte

//-------------------------------------------------------------------------------------------------------------------------
  private static final String CBC_CIPHER_INSTANCE  = "AES/CBC/PKCS5Padding";
  private static final String GCM_CIPHER_INSTANCE  = "AES/GCM/NoPadding";

//-------------------------------------------------------------------------------------------------------------------------
  public enum AESMode {
    CBC,
    GCM,
    ;
  }

//-------------------------------------------------------------------------------------------------------------------------
  // Tạo khóa AES với độ dài tùy chỉnh (128, 192, 256-bit)
  public static SecretKey generateAESKey(int keySize) throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(keySize);
    return keyGen.generateKey();
  }

//-------------------------------------------------------------------------------------------------------------------------
  // Chuyển đổi byte[] thành SecretKey
  public static SecretKey convertBytesToKey(byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, "AES");
  }

//-------------------------------------------------------------------------------------------------------------------------
  // Tạo IV ngẫu nhiên
  public static byte[] generateIV(AESMode mode) {
    int ivLength = (mode == AESMode.GCM) ? GCM_IV_LENGTH : CBC_IV_LENGTH;
    byte[] iv = new byte[ivLength];
    new SecureRandom().nextBytes(iv);
    return iv;
  }

//-------------------------------------------------------------------------------------------------------------------------
  // Mã hóa dữ liệu
  public static String encrypt(String plainText, byte[] secretKey, byte[] iv, AESMode mode) throws Exception {
    SecretKey aesKey = new SecretKeySpec(secretKey, "AES");
    return encrypt(plainText, aesKey, iv, mode);
  }
  public static String encrypt(String plaintext, SecretKey secretKey, byte[] iv, AESMode mode) throws Exception {
    Cipher cipher;
    if (mode == AESMode.GCM) {
      cipher = Cipher.getInstance(GCM_CIPHER_INSTANCE);
      GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
    }
    else {
      cipher = Cipher.getInstance(CBC_CIPHER_INSTANCE);
      IvParameterSpec ivSpec = new IvParameterSpec(iv);
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
    }
    
    byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    
    // Gộp IV + dữ liệu mã hóa
    byte[] combined = new byte[iv.length + encryptedBytes.length];
    System.arraycopy(iv, 0, combined, 0, iv.length);
    System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);
    
    return Base64.getEncoder().encodeToString(combined);
  }

//-------------------------------------------------------------------------------------------------------------------------
  // Giải mã dữ liệu
  public static String decrypt(String encryptedText, byte[] secretKey, AESMode mode) throws Exception {
    SecretKeySpec aesKey = new SecretKeySpec(secretKey, "AES");
    return decrypt(encryptedText, aesKey, mode);
  }
  public static String decrypt(String encryptedData, SecretKey secretKey, AESMode mode) throws Exception {
    byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
    int ivLength = (mode == AESMode.GCM) ? GCM_IV_LENGTH : CBC_IV_LENGTH;
    byte[] iv = new byte[ivLength];
    byte[] encryptedBytes = new byte[decodedBytes.length - ivLength];
    
    System.arraycopy(decodedBytes, 0, iv, 0, ivLength);
    System.arraycopy(decodedBytes, ivLength, encryptedBytes, 0, encryptedBytes.length);
    
    Cipher cipher;
    if (mode == AESMode.GCM) {
      cipher = Cipher.getInstance(GCM_CIPHER_INSTANCE);
      GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
      cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
    }
    else {
      cipher = Cipher.getInstance(CBC_CIPHER_INSTANCE);
      IvParameterSpec ivSpec = new IvParameterSpec(iv);
      cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
    }
    
    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
    return new String(decryptedBytes, StandardCharsets.UTF_8);
  }

//-------------------------------------------------------------------------------------------------------------------------
  public static void main(String[] args) throws Exception {
    String originalText = "Dữ liệu bảo mật với AES tổng quát";

    // Tạo khóa AES với độ dài 256-bit
    SecretKey secretKey = generateAESKey(256);

    // Chạy thử với AES-CBC
    byte[] ivCBC = generateIV(AESMode.CBC);
    String encryptedCBC = encrypt(originalText, secretKey, ivCBC, AESMode.CBC);
    System.out.println("AES-CBC Mã hóa: " + encryptedCBC);
    System.out.println("AES-CBC Giải mã: " + decrypt(encryptedCBC, secretKey, AESMode.CBC));

    // Chạy thử với AES-GCM
    byte[] ivGCM = generateIV(AESMode.GCM);
    String encryptedGCM = encrypt(originalText, secretKey, ivGCM, AESMode.GCM);
    System.out.println("AES-GCM Mã hóa: " + encryptedGCM);
    System.out.println("AES-GCM Giải mã: " + decrypt(encryptedGCM, secretKey, AESMode.GCM));
  }
}
