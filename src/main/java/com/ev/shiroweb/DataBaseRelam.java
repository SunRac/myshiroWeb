package com.ev.shiroweb;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.Set;

/**
 * @author java_shj
 * @desc
 * @createTime 2019/11/3 21:09
 **/
public class DataBaseRelam extends AuthorizingRealm {

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //进入这个方法说明已经通过了认证
        String userName = (String) principalCollection.getPrimaryPrincipal();
        //查询数据库，获取角色和权限信息
        Set<String> permits = new AccessDB4JDBC().listPermits(userName);
        Set<String> roles = new AccessDB4JDBC().listRoles(userName);
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.setRoles(roles);
        simpleAuthorizationInfo.setStringPermissions(permits);
        return simpleAuthorizationInfo;
    }

    /**
     * 继承的认证方法，验证用户名密码是否正确
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //取得token
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        //取得输入的用户名、密码
        String userName = (String) token.getPrincipal();
        String password = String.valueOf(token.getPassword());
        //查询数据库获取对应用户的密码
//        对密码进行加密后比对
//        String passwordDao = new AccessDB4JDBC().getPassword(userName);
        User user = new AccessDB4JDBC().getUser(userName);
        try{
            String encodePassword = new SimpleHash("md5", password, user.getSalt(), 2).toString();
            //判断密码是否正确，密码为空说明用户不存在
            if(user ==null || !encodePassword.equals(user.getPassword())){
                throw new AuthenticationException();
            }
        } catch (Exception e){
            throw new AuthenticationException();
        }
        //保存认证信息到authenticationInfo中
        return new SimpleAuthenticationInfo(userName,password,getName());
    }
}
