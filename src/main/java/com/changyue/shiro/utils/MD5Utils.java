package com.changyue.shiro.utils;

import org.apache.shiro.crypto.hash.Md5Hash;

/**
 * @program: shirodemo
 * @description: MD5工具类
 * @author: 袁阊越
 * @create: 2019-11-16 23:32
 */
public class MD5Utils {

    private static int hashCount = 3;

    /**
     * UUID随机生成码处理后的
     */
    private static final String PUBLIC_SALT = "832EC407D7AA4393A193D2BAF4747472";

    /**
     * 私有化
     *
     * @param source 公盐加密
     * @return MD5
     */
    private static String md5PublicSalt(String source) {
        return new Md5Hash(source, PUBLIC_SALT, hashCount).toString();
    }

    /**
     * 公用化
     *
     * @param source 原始密码
     * @param salt   私盐
     * @return MD5
     */
    public static String md5PrivateSalt(String source, String salt) {
        return new Md5Hash(md5PublicSalt(source), salt, hashCount).toString();
    }

}
