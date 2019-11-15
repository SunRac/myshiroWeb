package com.ev.shiroweb;

import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.SimpleHash;

import java.sql.*;
import java.util.HashSet;
import java.util.Set;

/**
 * @author java_shj
 * @desc 通过JDBC访问数据库，来获取用户登录信息
 * @createTime 2019/10/24 11:15
 **/
public class AccessDB4JDBC {
    private static final String getPassword = "select password from shiro_user where name = ?";
    private static final String listRoles = "select r.name from shiro_user u " +
                                            "left join shiro_user_role ur on u.id = ur.uid " +
                                            "left join shiro_role r on r.id = ur.rid where u.name = ?";
    private static final String listPermits = "select p.name from shiro_user u " +
                                            "left join shiro_user_role ru on u.id = ru.uid " +
                                            "left join shiro_role r on r.id = ru.rid " +
                                            "left join shiro_role_permission rp on r.id = rp.rid " +
                                            "left join shiro_permission p on p.id = rp.pid " +
                                            "where u.name =?";
    //构造方法中初始化驱动管理器
    public AccessDB4JDBC(){
        try {
            Class.forName(("com.mysql.jdbc.Driver"));
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        /*System.out.println( new AccessDB4JDBC().getPassword("zhang3"));
        System.out.println( new AccessDB4JDBC().listRoles("zhang3"));
        System.out.println( new AccessDB4JDBC().listPermits("zhang3"));
        System.out.println( new AccessDB4JDBC().getPassword("li4"));
        System.out.println( new AccessDB4JDBC().listRoles("li4"));
        System.out.println( new AccessDB4JDBC().listPermits("li4"));*/
        new AccessDB4JDBC().createUser("zhang3","12345");
        new AccessDB4JDBC().createUser("li4","abcde");
    }

    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://127.0.0.1:3306/eastlegend", "root", "xxzj2019");
    }

    public String getPassword(String userName) {
        try {
            Connection connection = getConnection();
            PreparedStatement preparedStatement = connection.prepareStatement(getPassword);
            preparedStatement.setString(1, userName);
            ResultSet resultSet = preparedStatement.executeQuery();
            if(resultSet.next()){
                return resultSet.getString("password");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }
    public Set<String> listRoles(String userName) {
        Set<String> roles = new HashSet<String>();
        try {
            Connection connection = getConnection();
            PreparedStatement preparedStatement = connection.prepareStatement(listRoles);
            preparedStatement.setString(1, userName);
            ResultSet resultSet = preparedStatement.executeQuery();
            while (resultSet.next()){
                roles.add(resultSet.getString(1));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return roles;
    }

    public Set<String> listPermits(String userName) {
        Set<String> permits = new HashSet<String>();
        try {
            Connection connection = getConnection();
            PreparedStatement preparedStatement = connection.prepareStatement(listPermits);
            preparedStatement.setString(1, userName);
            ResultSet resultSet = preparedStatement.executeQuery();
            while (resultSet.next()){
                permits.add(resultSet.getString(1));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return permits;
    }

    //新建用户
    public void createUser(String userName, String password){
        Connection connection = null;
        try {
            String salt = new SecureRandomNumberGenerator().nextBytes().toString();
            String encodePassword = new SimpleHash("md5", password, salt,2).toString();
            connection = getConnection();
            PreparedStatement preparedStatement = connection.prepareStatement("insert into  shiro_user values(null,?,?,?)");
            preparedStatement.setString(1, userName);
            preparedStatement.setString(2, encodePassword);
            preparedStatement.setString(3, salt);
            preparedStatement.execute();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    //查询用户信息
    public User getUser(String username){
        Connection connection = null;
        try {
            connection = getConnection();
            PreparedStatement preparedStatement = connection.prepareStatement("select * from shiro_user where name=?");
            preparedStatement.setString(1, username);
            ResultSet resultSet = preparedStatement.executeQuery();
            if(resultSet.next()){
                User user = new User();
                user.setId(resultSet.getString("id"));
                user.setName(resultSet.getString("name"));
                user.setPassword(resultSet.getString("password"));
                user.setSalt(resultSet.getString("salt"));
                return user;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }




}
