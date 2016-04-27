package com.hellonativetest.app;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ECDHUtil {
    //用到的密码算法
    public static final String KEY_ALGORITHM = "EC";
    public static final String SECRET_ALGORITHM = "TlsPremasterSecret";
    public static final String KEY_ASYMMETRIC = "ECDH";
    public static final String KEY_SYMMETRIC = "AES";

    //秘钥长度
    private static final int KEY_SIZE = 256;

    //公钥
    private static final String PUBLIC_KEY = "ECPublicKey";

    //私钥
    private static final String PRIVATE_KEY = "ECPrivateKey";

    /**
     * 初始化A方的公钥和私钥
     */
    public static Map<String, Object> initKey() throws Exception {
        //实例化密钥对生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);

        //初始化密钥对生成器
        keyPairGenerator.initialize(KEY_SIZE);

        //生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //A方公钥
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        //A方私钥
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        //将密钥对存储在Map中
        Map<String, Object> keyMap = new HashMap<>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    /**
     * 初始化B方的公钥和私钥
     */
    public static Map<String, Object> initKey(byte[] key) throws Exception {
        //解析A方公钥，转换公钥材料
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
        //实例化秘钥工厂
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        //产生B的公钥
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        //根据A的公钥构建B的私钥
        ECParameterSpec ecParameterSpec = ((ECPublicKey) publicKey).getParams();
        //实例化密钥对生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyFactory.getAlgorithm());
        //初始化密钥对生成器
        keyPairGenerator.initialize(ecParameterSpec);
        //产生密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //B的公钥
        ECPublicKey publicKey2 = (ECPublicKey) keyPair.getPublic();
        //B的私钥
        ECPrivateKey privateKey2 = (ECPrivateKey) keyPair.getPrivate();
        //将密钥对存储在Map中
        Map<String, Object> keyMap = new HashMap<>(2);
        keyMap.put(PUBLIC_KEY, publicKey2);
        keyMap.put(PRIVATE_KEY, privateKey2);
        return keyMap;
    }

    /**
     * 对称加密算法加密操作
     */
    public static byte[] encrypt(byte[] data, byte[] key) throws Exception {

        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_SYMMETRIC);
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed(key);
        keyGenerator.init(128 , secureRandom);
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] enCodeFormat = secretKey.getEncoded();
        SecretKeySpec keySpec = new SecretKeySpec(enCodeFormat, KEY_SYMMETRIC);

        //数据加密
        Cipher cipher = Cipher.getInstance(KEY_SYMMETRIC);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    /**
     * 对称加密算法解密操作
     */
    public static byte[] decrypt(byte[] data, byte[] key) throws Exception {

        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_SYMMETRIC);
        keyGenerator.init(128, new SecureRandom(key));
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] deCodeFormat = secretKey.getEncoded();
        SecretKeySpec keySpec = new SecretKeySpec(deCodeFormat, KEY_SYMMETRIC);

        //数据解密
        Cipher cipher = Cipher.getInstance(KEY_SYMMETRIC);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    /**
     * 使用公钥和私钥，合力生成对称加密算法的秘钥
     */
    public static byte[] getSecretKey(byte[] publicKey, byte[] privateKey) throws Exception {
        //实例化秘钥工厂
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        //初始化公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        PublicKey pubKey = keyFactory.generatePublic(x509EncodedKeySpec);
        //初始化私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        //实例化
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_ASYMMETRIC);

        keyAgreement.init(priKey);

        keyAgreement.doPhase(pubKey, true);

        //生成本地对称秘钥

        SecretKey secretKey = keyAgreement.generateSecret(SECRET_ALGORITHM);

        return secretKey.getEncoded();
    }


    /**
     * 获得私钥
     */
    public static byte[] getPrivateKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return key.getEncoded();
    }

    /**
     * 获得公钥
     */
    public static byte[] getPublicKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return key.getEncoded();
    }


    public static String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }


    public static byte[] hexStringToBytes(String hexString) {
        if (hexString == null || hexString.equals("")) {
            return null;
        }
        hexString = hexString.toUpperCase();
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
        }
        return d;
    }

    public static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }

}
