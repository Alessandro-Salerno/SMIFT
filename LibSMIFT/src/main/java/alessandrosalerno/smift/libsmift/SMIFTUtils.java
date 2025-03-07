package alessandrosalerno.smift.libsmift;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.text.StringEscapeUtils;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;

public class SMIFTUtils {
    public static class RSA {
        public static byte[] encrypt(byte[] data, Key key) {
            try {
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                return cipher.doFinal(data);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public static byte[] decrypt(byte[] data, Key key) {
            try {
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, key);
                return cipher.doFinal(data);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public static byte[] encrypt(String data, Key key) {
            return encrypt(data.getBytes(StandardCharsets.UTF_8), key);
        }

        public static byte[] decrypt(String data, Key key) {
            return decrypt(data.getBytes(StandardCharsets.UTF_8), key);
        }

        public static String encryptToString(byte[] data, Key key) {
            return new String(encrypt(data, key), StandardCharsets.UTF_8);
        }

        public static String decryptToString(byte[] data, Key key) {
            return new String(decrypt(data, key), StandardCharsets.UTF_8);
        }

        public static String encryptToString(String data, Key key) {
            return new String(encrypt(data, key), StandardCharsets.UTF_8);
        }

        public static String decryptToString(String data, Key key) {
            return new String(decrypt(data, key), StandardCharsets.UTF_8);
        }

        public static KeyPair newPair(int keysize) {
            try {
                SecureRandom secureRandom = new SecureRandom();
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(keysize, secureRandom);
                return keyPairGenerator.generateKeyPair();
            } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                return null;
            }
        }
    }

    public static class AES {
        public static byte[] encrypt(byte[] data, SecretKey key, IvParameterSpec iv) {
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key, iv);
                return cipher.doFinal(data);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public static byte[] decrypt(byte[] data, SecretKey key, IvParameterSpec iv) {
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, key, iv);
                return cipher.doFinal(data);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public static byte[] encrypt(String data, SecretKey key, IvParameterSpec iv) {
            return encrypt(data.getBytes(StandardCharsets.UTF_8), key, iv);
        }

        public static byte[] decrypt(String data, SecretKey key, IvParameterSpec iv) {
            return decrypt(data.getBytes(StandardCharsets.UTF_8), key, iv);
        }

        public static String encryptToString(byte[] data, SecretKey key, IvParameterSpec iv) {
            return new String(encrypt(data, key, iv), StandardCharsets.UTF_8);
        }

        public static String decryptToString(byte[] data, SecretKey key, IvParameterSpec iv) {
            return new String(decrypt(data, key, iv), StandardCharsets.UTF_8);
        }

        public static String encryptToString(String data, SecretKey key, IvParameterSpec iv) {
            return new String(encrypt(data, key, iv), StandardCharsets.UTF_8);
        }

        public static String decryptToString(String data, SecretKey key, IvParameterSpec iv) {
            return new String(decrypt(data, key, iv), StandardCharsets.UTF_8);
        }
    }

    public static class Strings {
        public static String escapeBytes(byte[] data) {
            String str = new String(data, StandardCharsets.UTF_8);
            return StringEscapeUtils.escapeJson(str);
        }

        public static String currentDate() {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(new Date());
            SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
            df.setTimeZone(TimeZone.getTimeZone("UTC"));
            return df.format(calendar.getTime());
        }

        public static String futureDate(int daysFromNow) {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(new Date());
            calendar.add(Calendar.DATE, daysFromNow);
            SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
            df.setTimeZone(TimeZone.getTimeZone("UTC"));
            return df.format(calendar.getTime());
        }
    }
}
