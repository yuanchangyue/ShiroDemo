package com.changyue.shrio.sys.shrio;

import com.changyue.shrio.sys.model.User;
import com.changyue.shrio.utils.MD5Utils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.HashSet;
import java.util.Set;

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
