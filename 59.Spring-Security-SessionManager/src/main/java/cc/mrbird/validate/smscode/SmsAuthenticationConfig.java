package cc.mrbird.validate.smscode;

import cc.mrbird.security.browser.UserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

/**
 * Spring Security Session管理
 * https://mrbird.cc/Spring-Security-Session-Manage.html
 */
@Component
public class SmsAuthenticationConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    @Autowired
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private UserDetailService userDetailService;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        SmsAuthenticationFilter smsAuthenticationFilter = new SmsAuthenticationFilter();

        // FIXME http.getSharedObject 获取共享对象。请注意，不考虑对象层次结构
        smsAuthenticationFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));

        smsAuthenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        smsAuthenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler);

        SmsAuthenticationProvider smsAuthenticationProvider = new SmsAuthenticationProvider();
        smsAuthenticationProvider.setUserDetailService(userDetailService);

        // FIXME AuthenticationManager 通常与 AuthenticationProvider 一起使用。
        //  AuthenticationProvider 是一个更具体的认证提供者，它实现了 AuthenticationManager 接口，并提供了具体的认证逻辑。
        //  例如，它可能会与数据库交互，验证用户提供的用户名和密码是否匹配，并返回相应的 Authentication 对象。
        http.authenticationProvider(smsAuthenticationProvider)
                .addFilterAfter(smsAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    }
}

/**
 * http.getSharedObject 方法用于从 HttpSecurity 对象中获取共享对象。在您的示例中，
 * 它被用于获取 AuthenticationManager 实例，并将其设置为 SmsAuthenticationFilter 的认证管理器。
 *
 * AuthenticationManager 是 Spring Security 中负责处理认证逻辑的接口。
 * 它封装了用户提供的认证信息（如用户名和密码）的验证过程，并返回一个表示认证结果的 Authentication 对象。
 *
 * 通过将 AuthenticationManager 传递给 SmsAuthenticationFilter，您使得该过滤器能够利用 Spring Security 的认证逻辑来处理用户的短信认证请求。
 * 这意味着 SmsAuthenticationFilter 将使用 AuthenticationManager 来验证用户提供的短信验证码，并生成相应的认证结果。
 *
 * 简而言之，http.getSharedObject(AuthenticationManager.class) 用于从 HttpSecurity 中获取共享的 AuthenticationManager 实例，
 * 并将其设置为 SmsAuthenticationFilter 的认证管理器，以便进行短信认证的处理。
 */











