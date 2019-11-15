package com.ev.shiroweb;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author java_shj
 * @desc
 * @createTime 2019/11/7 18:04
 **/
@WebServlet(name="loginServlet",urlPatterns = "/login")
public class LoginServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String name = req.getParameter("name");
        String password = req.getParameter("password");
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(name, password);
        try {
            subject.login(usernamePasswordToken);
            Session session = subject.getSession();
            session.setAttribute("subject", subject);
            resp.sendRedirect("");
        } catch (AuthenticationException e) {
            req.setAttribute("error", "验证失败了");
            req.getRequestDispatcher("login.jsp").forward(req, resp);
        }
    }
}
