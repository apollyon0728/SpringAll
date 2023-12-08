package cc.mrbird.validate.smscode;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 定义用于处理短信验证码登录请求的过滤器SmsAuthenticationFilter，
 * 同样的复制UsernamePasswordAuthenticationFilter源码并稍作修改
 *
 * https://mrbird.cc/Spring-Security-SmsCode.html
 *
 * SmsAuthenticationFilter(AbstractAuthenticationProcessingFilter) -> AuthenticationManager
 *  -> SmsAuthenticationProvider(AuthenticationProvider) -> UserDetailService -> UserDetails -> Authentication
 */
public class SmsAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public static final String MOBILE_KEY = "mobile";

    private String mobileParameter = MOBILE_KEY;
    private boolean postOnly = true;

    /**
     * 构造函数中指定了当请求为/login/mobile，请求方法为POST的时候该过滤器生效。
     * mobileParameter属性值为mobile，对应登录页面手机号输入框的name属性。
     *
     * attemptAuthentication方法从请求中获取到mobile参数值，
     * 并调用SmsAuthenticationToken的SmsAuthenticationToken(String mobile)构造方法创建了一个SmsAuthenticationToken。
     * 下一步就如流程图中所示的那样，SmsAuthenticationFilter将SmsAuthenticationToken交给AuthenticationManager处理。
     */

    public SmsAuthenticationFilter() {
        super(new AntPathRequestMatcher("/login/mobile", "POST"));
    }


    /**
     * 身份验证: 根据请求中提供的手机号码对用户进行身份验证。
     *
     * 执行实际的身份验证。
     * 实施应执行以下操作之一：
     * 返回已验证用户的填充身份验证令牌，表示身份验证成功
     * 返回null，表示认证过程仍在进行中。在返回之前，实现应执行完成该过程所需的任何其他工作。
     * 如果身份验证过程失败，则抛出AuthenticationException
     * 参数：
     * request – 从中提取参数并执行身份验证 response – 响应，如果实现必须执行重定向作为多阶段身份验证过程（例如 OpenID）的一部分，则可能需要该响应。
     * 返回：
     * 经过身份验证的用户令牌，如果身份验证不完整，则为 null。
     *
     * @param request The HttpServletRequest object containing the request information.
     * @param response The HttpServletResponse object used to send the response.
     * @return The Authentication object representing the authenticated user.
     * @throws AuthenticationException if the authentication method is not supported.
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

        /**
         * FIXME 在Spring Security中，认证处理都需要通过AuthenticationManager来代理，
         * 所以这里我们依旧将SmsAuthenticationToken交由AuthenticationManager处理。
         * 接着我们需要定义一个支持处理SmsAuthenticationToken对象的SmsAuthenticationProvider，
         * SmsAuthenticationProvider调用UserDetailService的loadUserByUsername方法来处理认证
         */
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    protected String obtainMobile(HttpServletRequest request) {
        return request.getParameter(mobileParameter);
    }

    protected void setDetails(HttpServletRequest request,
                              SmsAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    public void setMobileParameter(String mobileParameter) {
        Assert.hasText(mobileParameter, "mobile parameter must not be empty or null");
        this.mobileParameter = mobileParameter;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public final String getMobileParameter() {
        return mobileParameter;
    }
}
