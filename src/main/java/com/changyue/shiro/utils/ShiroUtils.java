package com.changyue.shiro.utils;

import com.changyue.shiro.sys.shiro.ShiroRealm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.Subject;

/**
 * @program: shirodemo
 * @description: shiro工具类
 * @author: 袁阊越
 * @create: 2019-11-16 21:47
 */
public class ShiroUtils {

    /**
     * 初始化shiro的运行环境
     */
    static {
        //1.初始化SecurityManger安全管理器
        DefaultSecurityManager sm = new DefaultSecurityManager();

        //2.配置用户的权限信息到安全管理器中
        //Realm realm = new IniRealm("classpath:shiro.ini");
        Realm shiroRealm = new ShiroRealm();

        //3.配置缓存管理器
       /* CacheManager cacheManager = new MemoryConstrainedCacheManager();
        sm.setCacheManager(cacheManager);*/

        CacheManager cacheManager = new EhCacheManager();
        sm.setCacheManager(cacheManager);


        sm.setRealm(shiroRealm);
        //4.使用SecurityUtils将securityManager设置到运行环境中
        SecurityUtils.setSecurityManager(sm);
    }

    /**
     * 主体登录
     *
     * @param username 用户名
     * @param password 密码
     * @return 登录主体
     */
    public static Subject login(String username, String password) {

        //1.创建需要认证的Subject SecurityUtils.getSubject()
        Subject subject = SecurityUtils.getSubject();
        //2.创建一个认证的token，记录用户的的身份和凭证（账号密码）
        AuthenticationToken usernamePasswordToken =
                new UsernamePasswordToken(username, password);
        //3.subject进行登录，认证检查
        subject.login(usernamePasswordToken);
        //用户认证的状态
        System.out.println("用户认证的状态：" + subject.isAuthenticated());
        return subject;
    }

}
