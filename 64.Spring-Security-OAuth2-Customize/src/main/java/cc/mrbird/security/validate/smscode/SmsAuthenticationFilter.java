package cc.mrbird.security.validate.smscode;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Spring Security短信验证码登录
 * https://mrbird.cc/Spring-Security-SmsCode.html
 *
 * SmsAuthenticationFilter(AbstractAuthenticationProcessingFilter) -> AuthenticationManager
 *  -> SmsAuthenticationProvider(AuthenticationProvider) -> UserDetailService -> UserDetails -> Authentication
 *
 *
 * 在Spring Security 5.1.4中，`AbstractAuthenticationProcessingFilter`类是处理基于表单的认证请求的抽象类。它提供了一个`attemptAuthentication`方法，用于尝试进行身份验证。
 *
 * `attemptAuthentication`方法接受一个`HttpServletRequest`对象作为参数，并返回一个`Authentication`对象。
 * 该方法的主要作用是解析请求参数并创建一个空的`Authentication`对象，以便后续的身份验证过程。
 */
public class SmsAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public static final String MOBILE_KEY = "mobile";

    private String mobileParameter = MOBILE_KEY;
    private boolean postOnly = true;


    /**
     * SmsAuthenticationFilter构造函数
     *
     * @param param1 请求匹配器，用于匹配请求路径和请求方法
     * @param param2 请求路径，用于匹配手机号登录请求
     * @param param3 请求方法，用于匹配POST请求
     */
    public SmsAuthenticationFilter() {
        super(new AntPathRequestMatcher("/login/mobile", "POST"));
    }


    /**
     * 尝试进行身份验证的方法。
     *
     * 执行实际的身份验证。
     * 实施应执行以下操作之一：
     * 返回已验证用户的填充身份验证令牌，表示身份验证成功
     * 返回null，表示认证过程仍在进行中。在返回之前，实现应执行完成该过程所需的任何其他工作。
     * 如果身份验证过程失败，则抛出AuthenticationException
     *
     * @param request HttpServletRequest对象，包含HTTP请求的相关信息
     * @param response HttpServletResponse对象，包含HTTP响应的相关信息
     * @return 返回进行身份验证的参数描述
     * @throws AuthenticationException 如果身份验证失败，则抛出AuthenticationException异常
     */
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }

        String mobile = obtainMobile(request);

        if (mobile == null) {
            mobile = "";
        }

        mobile = mobile.trim();

        SmsAuthenticationToken authRequest = new SmsAuthenticationToken(mobile);

        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * 获取手机号码
     *
     * @param request HttpServletRequest对象，用于获取请求参数
     * @return 手机号码
     */
    protected String obtainMobile(HttpServletRequest request) {
        return request.getParameter(mobileParameter);
    }

    /**
     * 设置认证请求的详细信息。
     *
     * @param request HTTP请求对象，用于构建认证请求的详细信息
     * @param authRequest 短信认证令牌对象，用于设置详细信息
     */
    protected void setDetails(HttpServletRequest request,
                              SmsAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    /**
     * 设置移动参数。
     *
     * @param mobileParameter 移动参数，不能为空或为null。
     */
    public void setMobileParameter(String mobileParameter) {
        Assert.hasText(mobileParameter, "mobile parameter must not be empty or null");
        this.mobileParameter = mobileParameter;
    }

    /**
     * 设置是否仅允许POST请求
     * @param postOnly 是否仅允许POST请求的布尔值
     */
    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public final String getMobileParameter() {
        return mobileParameter;
    }
}
