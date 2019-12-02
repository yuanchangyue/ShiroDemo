package com.changyue;

import com.changyue.shiro.utils.ShiroUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

import java.util.UUID;

/**
 * @program: shirodemo
 * @description: shiro 测试
 * @author: 袁阊越
 * @create: 2019-11-16 20:43
 */
public class ShiroTest {

    @Test
    public void shiroTest() {

        //1.初始化SecurityManger安全管理器
        DefaultSecurityManager sm = new DefaultSecurityManager();
        //2.配置用户的权限信息到安全管理器中
        Realm realm = new IniRealm("classpath:shiro.ini");
        sm.setRealm(realm);
        //3.使用SecurityUtils将securityManager设置到运行环境中
        SecurityUtils.setSecurityManager(sm);
        //4.创建需要认证的Subject SecurityUtils.getSubject()
        Subject subject = SecurityUtils.getSubject();
        //5.创建一个认证的token，记录用户的的身份和凭证（账号密码）
        AuthenticationToken usernamePasswordToken =
                new UsernamePasswordToken("zhangsan", "123456");

        //用户认证的状态
        System.out.println("用户认证的状态：" + subject.isAuthenticated());

        //6.subject进行登录，认证检查
        subject.login(usernamePasswordToken);
        //用户认证的状态
        System.out.println("用户认证的状态：" + subject.isAuthenticated());

        //7.检查授权资源
        System.out.println("用户是否拥有admin角色" + subject.hasRole("admin"));
        System.out.println("用户是否拥有public该角色" + subject.hasRole("admin"));

        //8.检查角色的权限
        System.out.println("用户是否有product:create的权限" + subject.isPermitted("product:create"));
        System.out.println("用户是否有多个权限" + subject.isPermitted("product:create", "product:insert")[1]);

        //9.subject信息
        System.out.println("用户名：" + subject.getPrincipal());

        //10.subject退出
        subject.logout();

        //用户认证的状态
        System.out.println("用户认证的状态：" + subject.isAuthenticated());

    }


    @Test
    public void testShrioUtils() {
        //登录object
        Subject subject = ShiroUtils.login("zhangsan", "123456");
        //检查授权资源
        System.out.println("用户是否拥有admin角色" + subject.hasRole("admin"));
        //subject退出
        subject.logout();
        //用户认证的状态
        System.out.println("用户认证的状态：" + subject.isAuthenticated());
    }

    @Test
    public void testShrioRealm() {

        Subject subject = ShiroUtils.login("zhangsan", "123456");

        //用户触发某个按钮-->需要验证权限
        System.out.println("检查新增的用户的权限" + subject.isPermitted("sys:user:create"));
        System.out.println("检查新增的角色的权限" + subject.isPermitted("sys:role:create"));

        System.out.println("检查给用户是否是系统管理员" + subject.hasRole("系统管理员"));
        System.out.println("检查给用户是否是系统运维" + subject.hasRole("系统运维"));

        subject.logout();

    }


    @Test
    public void testMD5() {

        Md5Hash md5Hash = new Md5Hash("123");
        System.out.println(md5Hash);

        Md5Hash md5HashWithSalt = new Md5Hash("123", UUID.randomUUID().toString());
        System.out.println(md5HashWithSalt);

        Md5Hash md5HashWithSalt_2 = new Md5Hash("123", UUID.randomUUID().toString(), 2);
        System.out.println(md5HashWithSalt_2);

    }

    /**
     * 测试结果 4d669a8578bfd2bf309ae16e198263f4
     */
    @Test
    public void testPasswordWithMD5() {

   /*     //模拟客户端接收到的用户名和密码 （明文）
        String username = "zhangsan";
        String password = "123456";*/

       /* String str = username + password;
        // 将密码加上其它信息生成salt
        // 破解密码,需要破解salt
        // 破解salt,又要需要破解密码
        String salt = MD5Utils.md5GeneratedSalt(str);
        //最后加密密码
        password = MD5Utils.md5(password, salt);*/

        Subject subject = ShiroUtils.login("zhangsan", "123456");
        //用户认证的状态
        System.out.println("用户认证的状态：" + subject.isAuthenticated());
    }


    @Test
    public void testUUID() {
        // System.out.println(UUID.randomUUID().toString().toUpperCase().replace("-", ""));
        // System.out.println(MD5Utils.md5PublicSalt("123456"));
        //System.out.println(MD5Utils.md5PrivateSalt("123456", "f4af64b5c211be990ec6f26feef0f1ff"));
    }

    @Test
    public void testCaching() {

        Subject subject = ShiroUtils.login("zhangsan", "123456");

        //用户触发某个按钮-->需要验证权限
        System.out.println("检查新增的用户的权限" + subject.isPermitted("sys:user:create"));
        System.out.println("检查新增的用户的权限" + subject.isPermitted("sys:user:create"));

    }
}











