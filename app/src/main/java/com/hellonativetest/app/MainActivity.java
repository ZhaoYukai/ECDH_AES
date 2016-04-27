package com.hellonativetest.app;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;

import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

public class MainActivity extends AppCompatActivity {

    public static final String BASE_URL = "http://10.10.201.147:8080/CryptTest/android/";
    public static final String LOGIN_URL = BASE_URL + "aesservlet.jsp";
    public static final String GET_SECRET = BASE_URL + "getSecret.jsp";
    String aes_key;

    //服务器端的公钥
    private byte[] publicKeyServer = null;
    //客户端的公钥
    private byte[] publicKeyClient = null;
    //客户端的私钥
    private byte[] privateKeyClient = null;
    //客户端的AES密钥
    private byte[] secretKeyClient = null;

    MainActivity() {
        //发送一个空的请求
        try {
            String getPublicKeyStr = HttpNoCookieUtil.getRequest(GET_SECRET);
            JSONObject jsonObject = new JSONObject(getPublicKeyStr);
            String publicKeyServerStr = jsonObject.getString("publicKeyServerStr");
            //公钥字符串转换为字节数组

            publicKeyServer = Base64.decode(publicKeyServerStr, Base64.DEFAULT);
            //由服务端的公钥生成一个秘钥对生成器
            Map<String, Object> keyMap = ECDHUtil.initKey(publicKeyServer);
            //生成客户端的公钥和私钥
            publicKeyClient = ECDHUtil.getPublicKey(keyMap);
            privateKeyClient = ECDHUtil.getPrivateKey(keyMap);
            //生成AES算法的密钥
            secretKeyClient = ECDHUtil.getSecretKey(publicKeyServer, privateKeyClient);
            aes_key = Base64.encodeToString(secretKeyClient , Base64.DEFAULT);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        String crypt_data = "哇这么多！！！真是辛苦师哥了！";

        final MagicCrypt mc = new MagicCrypt(aes_key, 128);
        String en = mc.encrypt(crypt_data);

        Map<String , String> secmap = new HashMap<>();
        secmap.put("clientKey" , Base64.encodeToString(publicKeyClient , Base64.DEFAULT));
        secmap.put("crypt_data" , en);
        try {
            String res = HttpNoCookieUtil.postRequest(LOGIN_URL , secmap);
        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }


}
