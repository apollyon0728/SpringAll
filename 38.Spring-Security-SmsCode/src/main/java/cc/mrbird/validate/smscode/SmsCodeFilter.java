package cc.mrbird.validate.smscode;

import cc.mrbird.validate.code.ValidateCodeException;
import cc.mrbird.web.controller.ValidateController;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.social.connect.web.HttpSessionSessionStrategy;
import org.springframework.social.connect.web.SessionStrategy;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 * OncePerRequestFilter
 *
 * 过滤器基类，旨在保证在任何 Servlet 容器上每个请求分派单次执行。它提供了带有 HttpServletRequest 和 HttpServletResponse 参数的doFilterInternal方法。
 *
 * 从 Servlet 3.0 开始，过滤器可以作为单独线程中发生的REQUEST或ASYNC调度的一部分来调用。
 * 可以在web.xml中配置过滤器是否应参与异步调度。然而，在某些情况下，Servlet 容器采用不同的默认配置。
 * 因此，子类可以重写shouldNotFilterAsyncDispatch()方法来静态声明它们是否确实应该在两种类型的分派期间调用一次
 * ，以便提供线程初始化、日志记录、安全性等。此机制补充但不会取代在web.xml中使用调度程序类型配置过滤器的需要。
 *
 * 子类可以使用isAsyncDispatch(HttpServletRequest)来确定何时调用过滤器作为异步调度的一部分，
 * 并使用isAsyncStarted(HttpServletRequest)来确定何时将请求置于异步模式，因此当前调度不会是最后一个对于给定的请求。
 *
 * 另一种也发生在其自己线程中的调度类型是ERROR 。如果子类希望静态声明是否应在错误分派期间调用一次，
 * 则可以重写shouldNotFilterErrorDispatch() 。
 * getAlreadyFilteredAttributeName方法确定如何识别请求已被过滤。默认实现基于具体过滤器实例的配置名称。
 *
 *
 * SmsAuthenticationFilter(AbstractAuthenticationProcessingFilter) -> AuthenticationManager
 *  -> SmsAuthenticationProvider(AuthenticationProvider) -> UserDetailService -> UserDetails -> Authentication
 */
@Component
public class SmsCodeFilter extends OncePerRequestFilter {

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;

    private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        if (StringUtils.equalsIgnoreCase("/login/mobile", httpServletRequest.getRequestURI())
                && StringUtils.equalsIgnoreCase(httpServletRequest.getMethod(), "post")) {
            try {
                validateCode(new ServletWebRequest(httpServletRequest));
            } catch (ValidateCodeException e) {
                authenticationFailureHandler.onAuthenticationFailure(httpServletRequest, httpServletResponse, e);
                return;
            }
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    /**
     * 验证验证码的有效性
     * @param servletWebRequest 请求对象
     * @throws ServletRequestBindingException 请求参数绑定异常
     * @throws ValidateCodeException 验证码异常
     */
    private void validateCode(ServletWebRequest servletWebRequest) throws ServletRequestBindingException {
        String smsCodeInRequest = ServletRequestUtils.getStringParameter(servletWebRequest.getRequest(), "smsCode");
        String mobileInRequest = ServletRequestUtils.getStringParameter(servletWebRequest.getRequest(), "mobile");

        SmsCode codeInSession = (SmsCode) sessionStrategy.getAttribute(servletWebRequest, ValidateController.SESSION_KEY_SMS_CODE + mobileInRequest);


        if (StringUtils.isBlank(smsCodeInRequest)) {
            throw new ValidateCodeException("验证码不能为空！");
        }

        if (codeInSession == null) {
            throw new ValidateCodeException("验证码不存在！");
        }

        if (codeInSession.isExpire()) {
            sessionStrategy.removeAttribute(servletWebRequest, ValidateController.SESSION_KEY_IMAGE_CODE);
            throw new ValidateCodeException("验证码已过期！");
        }

        // FIXME 手机验证码是否一致 （用户请求发送过来的 和 sessionStrategy 中的进行对比）
        if (!StringUtils.equalsIgnoreCase(codeInSession.getCode(), smsCodeInRequest)) {
            throw new ValidateCodeException("验证码不正确！");
        }
        sessionStrategy.removeAttribute(servletWebRequest, ValidateController.SESSION_KEY_IMAGE_CODE);

    }
}