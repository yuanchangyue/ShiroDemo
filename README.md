# ShiroDemo
shrio 练习

## 简介
> Apache Shiro 是 Java 的一个安全框架。目前，使用 Apache Shiro 的人越来越多，因为它相当简单，对比 Spring Security，可能没有 Spring Security 做的功能强大，但是在实际工作时可能并不需要那么复杂的东西，所以使用小而简单的 Shiro 就足够了。对于它俩到底哪个好，这个不必纠结，能更简单的解决项目问题就好了。

## 概念

## 使用

### 依赖

```xml
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.11</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>commons-logging</groupId>
      <artifactId>commons-logging</artifactId>
      <version>1.1.3</version>
    </dependency>
    <dependency>
      <groupId>org.apache.shiro</groupId>
      <artifactId>shiro-core</artifactId>
      <version>1.3.2</version>
    </dependency>
```

### 配置文件

```xml
[users]
zhangsan=123456,admin
lisi=123123,superadmin

[roles]
admin=product:create,product:delete,product:update,product:view
public=product:view

```

### 读取配置类

```java
//1.初始化SecurityManger安全管理器
DefaultSecurityManager sm = new DefaultSecurityManager();
//2.配置用户的权限信息到安全管理器中
Realm realm = new IniRealm("classpath:shrio.ini");
sm.setRealm(realm);
//3.使用SecurityUtils将securityManager设置到运行环境中
SecurityUtils.setSecurityManager(sm);
```

因为没有slf4j的配置，运行控制台报出
```shell script
SLF4J: Failed to load class "org.slf4j.impl.StaticLoggerBinder".
SLF4J: Defaulting to no-operation (NOP) logger implementation
SLF4J: See http://www.slf4j.org/codes.html#StaticLoggerBinder for further details.
```

加上log4j和slf4j 桥接
```xml
<!-- log4j 和 slf4j 桥接 -->
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-slf4j-impl</artifactId>
  <version>2.12.1</version>
  <scope>test</scope>
</dependency>
```

控制台打印
```shell script
2019-11-16 21:13:55 DEBUG [main][ResourceUtils.java:159] - Opening resource from class path [shrio.ini]
2019-11-16 21:13:55 DEBUG [main][Ini.java:351] - Parsing [users]
2019-11-16 21:13:55 DEBUG [main][Ini.java:351] - Parsing [roles]
2019-11-16 21:13:55 DEBUG [main][IniRealm.java:179] - Discovered the [roles] section.  Processing...
2019-11-16 21:13:55 DEBUG [main][IniRealm.java:185] - Discovered the [users] section.  Processing...
```

### 实例
```java
//1.初始化SecurityManger安全管理器
DefaultSecurityManager sm = new DefaultSecurityManager();
//2.配置用户的权限信息到安全管理器中
Realm realm = new IniRealm("classpath:shrio.ini");
sm.setRealm(realm);
//3.使用SecurityUtils将securityManager设置到运行环境中
SecurityUtils.setSecurityManager(sm);
//4.创建需要认证的Subject SecurityUtils.getSubject()
Subject subject = SecurityUtils.getSubject();
//5.创建一个认证的token，记录用户的的身份和凭证（账号密码）
AuthenticationToken usernamePasswordToken =
        new UsernamePasswordToken("zhangsan","123456");
//6.subject进行登录，认证检查
subject.login(usernamePasswordToken);
```
shrio.ini中有用户为zhangsan密码为123456的user
运行结果：

账号输入错误的抛出
```shell script
org.apache.shiro.authc.UnknownAccountException: Realm [org.apache.shiro.realm.text.IniRealm@54c562f7] was unable to find account data for the submitted AuthenticationToken [org.apache.shiro.authc.UsernamePasswordToken - zhangsans, rememberMe=false].
```
密码输入错误的抛出
```shell script
org.apache.shiro.authc.IncorrectCredentialsException: Submitted credentials for token [org.apache.shiro.authc.UsernamePasswordToken - zhangsan, rememberMe=false] did not match the expected credentials.
```

其他的常见操作
```java
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
System.out.println("用户名："+subject.getPrincipal());
//10.subject退出
subject.logout();
//用户认证的状态
System.out.println("用户认证的状态：" + subject.isAuthenticated());
```
运行结果:


## 封装ShrioUtils
```java
/**
 * @program: shirodemo
 * @description: shrio工具类
 * @author: 袁阊越
 * @create: 2019-11-16 21:47
 */
public class ShrioUtils {

    /**
     * 初始化shrio的运行环境
     */
    static {
        //1.初始化SecurityManger安全管理器
        DefaultSecurityManager sm = new DefaultSecurityManager();
        //2.配置用户的权限信息到安全管理器中
        Realm realm = new IniRealm("classpath:shrio.ini");
        sm.setRealm(realm);
        //3.使用SecurityUtils将securityManager设置到运行环境中
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
```

测试：
```java
    @Test
    public void testShrioUtils() {
        //登录object
        Subject subject = ShrioUtils.login("zhangsan", "123456");
        //检查授权资源
        System.out.println("用户是否拥有admin角色" + subject.hasRole("admin"));
        //subject退出
        subject.logout();
        //用户认证的状态
        System.out.println("用户认证的状态：" + subject.isAuthenticated());
    }
```
测试结果：

## 自定义Realm

+ 认证

继承`AuthorizingRealm`
```java
/**
 * @program: shirodemo
 * @description: 自定义realm
 * @author: 袁阊越
 * @create: 2019-11-16 22:04
 */
public class ShrioRealm extends AuthorizingRealm {

    /**
     * 授权资源检查
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println("授权资源检查...");
        return null;
    }

    /**
     * 登录认证
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;

        //1. 获取用户的用户名
        String username = token.getUsername();
        //2. 获取用户的密码
        String password = new String(token.getPassword());

        //3. 根据用户名去数据库中查询用户是否存在  模拟操作
        User user = new User("zhangsan", "123456");
        if (!user.getUsername().equals(username)) {
            throw new UnknownAccountException("用户不存在");
        }
        if (!user.getPassword().equals(password)) {
            throw new CredentialsException("密码错误");
        }
        System.out.println("登录认证...");
        return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName());
    }
}
```
测试类：
```java
    @Test
    public void testShrioUtils() {
        //登录object
        Subject subject = ShrioUtils.login("zhangsan", "123456");
        //检查授权资源
        System.out.println("用户是否拥有admin角色" + subject.hasRole("admin"));
        //subject退出
        subject.logout();
        //用户认证的状态
        System.out.println("用户认证的状态：" + subject.isAuthenticated());
    }
```
测试自定义的Realm：


+ 授权
```java
/**
 * @program: shirodemo
 * @description: 自定义realm
 * @author: 袁阊越
 * @create: 2019-11-16 22:04
 */
public class ShrioRealm extends AuthorizingRealm {

    /**
     * 授权
     * 将认证的通过的用户信息和权限信息设置给认证的主体
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

        //用户的身份信息
        String username = principals.getPrimaryPrincipal().toString();

        //通过username从数据库获取当前用户的角色
        Set<String> rolesNames = new HashSet<>();
        rolesNames.add("系统管理员");
        rolesNames.add("系统运维");
        //从数据库获取当前用户的权限
        Set<String> permissionName = new HashSet<>();
        permissionName.add("sys:user:create");
        permissionName.add("sys:user:update");
        permissionName.add("sys:user:list");
        permissionName.add("sys:user:delete");
        permissionName.add("sys:user:info");

        //简单授权的信息，对象的中包含用户的角色和权限信息
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.addRoles(rolesNames);
        info.addStringPermissions(permissionName);

        System.out.println("授权...");
        return info;
    }

    /**
     * 认证
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;

        //1. 获取用户的用户名
        String username = token.getUsername();
        //2. 获取用户的密码
        String password = new String(token.getPassword());

        //3. 根据用户名去数据库中查询用户是否存在
        User user = new User("zhangsan", "123456");
        if (!user.getUsername().equals(username)) {
            throw new UnknownAccountException("用户不存在");
        }
        if (!user.getPassword().equals(password)) {
            throw new CredentialsException("密码错误");
        }
        System.out.println("登录认证...");
        return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName());
    }
}

```
测试类：

```java

@Test
    public void testShrioRealm() {

        Subject subject = ShrioUtils.login("zhangsan", "123456");

        //用户触发某个按钮-->需要验证权限
        System.out.println("检查新增的用户的权限" + subject.isPermitted("sys:user:create"));
        System.out.println("检查新增的角色的权限" + subject.isPermitted("sys:role:create"));

        System.out.println("检查给用户是否是系统管理员"+subject.hasRole("系统管理员"));
        System.out.println("检查给用户是否是系统运维"+subject.hasRole("系统运维"));

        subject.logout();

    }

```
运行结果：


## Shrio异常

+ `org.apache.shiro.authc.UnknownAccountException`        用户名不存在
+ `org.apache.shiro.authc.CredentialsException`           认证不合法
+ `org.apache.shiro.authc.DisabledAccountException`       账号禁用
+ `org.apache.shiro.authc.LockedAccountException`         账号锁定
+ `org.apache.shiro.authc.ExpiredCredentialsException`    凭证过期
+ `org.apache.shiro.authc.AuthenticationException`        认证异常
 

## 密码加密
### 散列算法


>散列算法可以把[任意尺寸]的数据(原始数据)转变为一个[固定尺寸]的”小数据”(叫”散列值”或”摘要”)
>特点： 1.不可逆性 2.确定性

但是....

>直接对密码进行散列，可以对通过获得这个密码散列值，通过MD5密码破解网站得到某用户的密码。 不安全

于是：

>加Salt可以一定程度上解决这一问题。所谓加Salt方法，就是加点“佐料”。其基本想法是这样的：当用户首次提供密码时（通常是注册时），由系统自动往这个密码里撒一些“佐料”，然后再散列。而当用户登录时，系统为用户提供的代码撒上同样的“佐料”，然后散列，再比较散列值，已确定密码是否正确。
>这里的“佐料”被称作“Salt值”，这个值是由系统随机生成的，并且只有系统知道。这样，即便两个用户使用了同一个密码，由于系统为它们生成的salt值不同，他们的散列值也是不同的。即便黑客可以通过自己的密码和自己生成的散列值来找具有特定密码的用户，但这个几率太小了

直接MD5加密
```java
Md5Hash md5Hash = new Md5Hash("123");
System.out.println(md5Hash);
```
得到：`202cb962ac59075b964b07152d234b70`
去 https://www.cmd5.com/ 破解
如图：

采用加盐和多次hash
```java
 Md5Hash md5HashWithSalt = new Md5Hash("123", UUID.randomUUID().toString());
 System.out.println(md5HashWithSalt);

 Md5Hash md5HashWithSalt_2 = new Md5Hash("123", UUID.randomUUID().toString(), 2);
 System.out.println(md5HashWithSalt_2);
```
如图：


### MD5Utils
```java
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
    private static final String PRIVATE_SALT = "832EC407D7AA4393A193D2BAF4747472";
    
    /**
     * 生成DM5
     *
     * @param source 生成数据
     * @param salt   盐
     * @return MD5
     */
    public static String md5(String source, String salt) {
        return new Md5Hash(source, salt, hashCount).toString();
    }

    /**
     * 生成盐
     *
     * @param source 生成数据
     * @return MD5
     */
    public static String md5GeneratedSalt(String source) {
        return new Md5Hash(source, PRIVATE_SALT, hashCount).toString();

    }
}

```
测试类：
```java
    /**
     * 测试结果 4d669a8578bfd2bf309ae16e198263f4
     */
    @Test
    public void testPasswordWithMD5() {

        //模拟客户端接收到的用户名和密码 （明文）
        String username = "zhangsan";
        String password = "123456";

        String str = username + password;
        // 将密码加上其它信息生成salt
        // 破解密码,需要破解salt
        // 破解salt,又要需要破解密码
        String salt = MD5Utils.md5GeneratedSalt(str);
        //最后加密密码
        password = MD5Utils.md5(password, salt);

        Subject subject = ShrioUtils.login("zhangsan", password);
        //用户认证的状态
        System.out.println("用户认证的状态：" + subject.isAuthenticated());
    }
```
存入数据库的密码MD5加密成：`4d669a8578bfd2bf309ae16e198263f4`
测试结果：

### 更进一步

>用户注册的时候,为每一个用户生成一个私盐, 将用户私盐用系统的公盐加密,最后得到密码的盐

+ 升级的MD5Utils
```java
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
```
+ 自定的Realm
```java
/**
 * @program: shirodemo
 * @description: 自定义realm
 * @author: 袁阊越
 * @create: 2019-11-16 22:04
 */
public class ShrioRealm extends AuthorizingRealm {

    /**
     * 授权
     * 将认证的通过的用户信息和权限信息设置给认证的主体
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

        //用户的身份信息
        String username = principals.getPrimaryPrincipal().toString();

        //通过username从数据库获取当前用户的角色
        Set<String> rolesNames = new HashSet<>();
        rolesNames.add("系统管理员");
        rolesNames.add("系统运维");
        //从数据库获取当前用户的权限
        Set<String> permissionName = new HashSet<>();
        permissionName.add("sys:user:create");
        permissionName.add("sys:user:update");
        permissionName.add("sys:user:list");
        permissionName.add("sys:user:delete");
        permissionName.add("sys:user:info");

        //简单授权的信息，对象的中包含用户的角色和权限信息
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.addRoles(rolesNames);
        info.addStringPermissions(permissionName);

        System.out.println("授权...");
        return info;
    }

    /**
     * 认证
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;

        //1. 获取用户的用户名
        String username = token.getUsername();
        //2. 获取用户的密码
        String password = new String(token.getPassword());

        //3. 根据用户名去数据库中查询用户是否存在
        //3. 模拟获得用户在数据库的信息
        User user = new User("zhangsan", "6d58d495d0517b4e7205346a72e211bc", 0, "f4af64b5c211be990ec6f26feef0f1ff");
        //3. 明文加密
        password = MD5Utils.md5PrivateSalt(password, user.getPrivateSalt());

        if (!user.getUsername().equals(username)) {
            throw new UnknownAccountException("用户不存在");
        }

        if (!user.getPassword().equals(password)) {
            throw new CredentialsException("密码错误");
        }

        if (user.getStatus() == 1) {
            throw new DisabledAccountException("账号被禁用");
        }

        if (user.getStatus() == 2) {
            throw new LockedAccountException("账号被锁定");
        }

        System.out.println("登录认证...");
        return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName());
    }
}
```

测试结果：





 











