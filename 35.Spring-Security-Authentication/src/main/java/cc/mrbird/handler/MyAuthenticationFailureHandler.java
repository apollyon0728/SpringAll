package cc.mrbird.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义登录失败逻辑
 *
 * Spring Security自定义用户认证
 * https://mrbird.cc/Spring-Security-Authentication.html
 */
@Component
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Autowired
    private ObjectMapper mapper;

    /**
     * `onAuthenticationFailure`方法的`AuthenticationException`参数是一个抽象类
     * ，Spring Security根据登录失败的原因封装了许多对应的实现类，查看`AuthenticationException`的Hierarchy：
     *
     * 不同的失败原因对应不同的异常，
     * 比如用户名或密码错误对应的是`BadCredentialsException`，
     * 用户不存在对应的是`UsernameNotFoundException`，
     * 用户被锁定对应的是`LockedException`等。
     *
     * @param request the request during which the authentication attempt occurred.
     * @param response the response.
     * @param exception the exception which was thrown to reject the authentication
     * request.
     * @throws IOException
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(mapper.writeValueAsString(exception.getMessage()));
    }
}
