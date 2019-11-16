package com.changyue.shrio.sys.model;

/**
 * @program: shirodemo
 * @description: 用户
 * @author: 袁阊越
 * @create: 2019-11-16 22:16
 */
public class User {
    private String username;
    private String password;
    /**
     * 用户状态
     * 0:异常 1:禁用 2:锁定
     */
    private Integer status;
    private String privateSalt;

    public User(String username, String password, Integer status, String privateSalt) {
        this.username = username;
        this.password = password;
        this.status = status;
        this.privateSalt = privateSalt;
    }

    public User(String username, String password, Integer status) {
        this.username = username;
        this.password = password;
        this.status = status;
    }


    public String getPrivateSalt() {
        return privateSalt;
    }

    public void setPrivateSalt(String privateSalt) {
        this.privateSalt = privateSalt;
    }

    public Integer getStatus() {
        return status;
    }

    public void setStatus(Integer status) {
        this.status = status;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
