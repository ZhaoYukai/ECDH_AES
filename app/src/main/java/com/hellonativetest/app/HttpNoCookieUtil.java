package com.hellonativetest.app;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;

/**
 * 本类中的两个方法用于向服务器发送请求，方法返回服务器的响应
 * 接下来在Android应用中只要调用这两个方法即可实现与服务器的通信
 */
public class HttpNoCookieUtil {

    //创建HttpClient对象
    public static HttpClient httpClient = new DefaultHttpClient();

    /**
     * 发送get请求调用的方法
     *
     * @param url 发送请求的url
     * @return 服务器响应字符串
     * @throws Exception
     */
    public static String getRequest(final String url) throws Exception {
        //这样的一个task做了很多事
        FutureTask<String> task = new FutureTask<>(
                new Callable<String>() {
                    @Override
                    public String call() throws Exception {
                        //创建HttpGet对象
                        HttpGet get = new HttpGet(url);
                        //发送Get请求
                        HttpResponse httpResponse = httpClient.execute(get);
                        //如果服务器成功地返回响应
                        if (httpResponse.getStatusLine().getStatusCode() == 200) {
                            //获取服务器响应字符串
                            String result = EntityUtils.toString(httpResponse.getEntity());
                            return result;
                        }
                        return null;
                    }
                }
        );

        //开启子线程
        new Thread(task).start();

        return task.get();
    }


    /**
     * 发送post请求调用的方法
     *
     * @param url       发送请求的url
     * @param rawParams 请求的参数
     * @return 服务器响应的字符串
     * @throws Exception
     */
    public static String postRequest(final String url, final Map<String, String> rawParams) throws Exception {

        //一个task要做很多事
        FutureTask<String> task = new FutureTask<>(
                new Callable<String>() {
                    @Override
                    public String call() throws Exception {
                        //创建HttpPost对象
                        HttpPost httpPost = new HttpPost(url);
                        //对传递的参数进行封装
                        List<NameValuePair> params = new ArrayList<>();
                        for (String key : rawParams.keySet()) {
                            //对参数进行封装
                            params.add(new BasicNameValuePair(key, rawParams.get(key)));
                        }
                        //设置请求参数
                        httpPost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));

                        //发送post请求
                        HttpResponse httpResponse = httpClient.execute(httpPost);
                        //如果服务器成功的返回响应
                        if (httpResponse.getStatusLine().getStatusCode() == 200) {
                            //获取服务器响应字符串
                            String result = EntityUtils.toString(httpResponse.getEntity());
                            return result;
                        }
                        return null;
                    }
                }
        );

        new Thread(task).start();
        return task.get();
    }


}