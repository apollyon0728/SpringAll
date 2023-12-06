package cc.mrbird.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * 自定义登录成功逻辑
 *
 * Spring Security自定义用户认证
 * https://mrbird.cc/Spring-Security-Authentication.html
 */
@Component
public class MyAuthenticationSucessHandler implements AuthenticationSuccessHandler {

    // private RequestCache requestCache = new HttpSessionRequestCache();

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    //
    // @Autowired
    // private ObjectMapper mapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        // FIXME 用户登录成功后页面将打印出`Authentication`对象的信息
        // response.setContentType("application/json;charset=utf-8");
        // response.getWriter().write(mapper.writeValueAsString(authentication));

        // FIXME 登录成功后做页面的跳转
        // SavedRequest savedRequest = requestCache.getRequest(request, response);
        // System.out.println(savedRequest.getRedirectUrl());
        // redirectStrategy.sendRedirect(request, response, savedRequest.getRedirectUrl());

        // FIXME 登录成功后页面将跳转回引发跳转的页面。如果想指定跳转的页面，
        //  比如跳转到`/index`，可以将`savedRequest.getRedirectUrl()`修改为`/index`：
        redirectStrategy.sendRedirect(request, response, "/index");
    }
}
