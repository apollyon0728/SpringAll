package cc.mrbird.web.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author MrBird
 */
@RestController
public class BrowserSecurityController {

    private RequestCache requestCache = new HttpSessionRequestCache();

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /**
     * `HttpSessionRequestCache`为Spring Security提供的用于缓存请求的对象，
     * 通过调用它的`getRequest`方法可以获取到本次请求的HTTP信息。
     *
     * `DefaultRedirectStrategy`的`sendRedirect`为Spring Security提供的用于处理重定向的方法。
     *
     * 上面代码获取了引发跳转的请求，根据请求是否以`.html`为结尾来对应不同的处理方法。
     * 如果是以`.html`结尾，那么重定向到登录页面，否则返回”访问的资源需要身份认证！”信息，并且HTTP状态码为401（`HttpStatus.UNAUTHORIZED`）。
     *
     * 这样当我们访问http://localhost:8080/hello的时候页面便会跳转到http://localhost:8080/authentication/require，
     * 并且输出”访问的资源需要身份认证！”，当我们访问http://localhost:8080/hello.html的时候，页面将会跳转到登录页面。
     *
     * @param request
     * @param response
     * @return
     * @throws IOException
     */
    @GetMapping("/authentication/require")
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public String requireAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException {
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl();
            if (StringUtils.endsWithIgnoreCase(targetUrl, ".html"))
                redirectStrategy.sendRedirect(request, response, "/login.html");
        }
        return "访问的资源需要身份认证！";
    }
}
