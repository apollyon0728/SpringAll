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
 * `SecurityConfigurerAdapter`是Spring Security中一个重要的抽象类，它提供了配置Spring Security安全性的基础方法。
 * 通常，我们会通过继承`SecurityConfigurerAdapter`来创建自定义的`WebSecurityConfigurerAdapter`，
 * 以便在Web应用场景下配置Spring Security。
 *
 * 在`SecurityConfigurerAdapter`中，我们可以覆盖一些方法来自定义安全性配置，例如：
 *
 * - `configure(HttpSecurity http)`：这个方法允许我们配置HTTP请求如何被安全性处理。
 * 例如，我们可以添加认证和授权规则、定义如何处理表单登录等。
 *
 * - `configure(AuthenticationManagerBuilder auth)`：
 * 这个方法允许我们配置认证管理器的构建过程，例如定义如何创建和管理用户认证。
 *
 * 通过覆盖这些方法，我们可以完全自定义Spring Security的配置，以满足特定的应用需求。
 */
@Component
public class SmsAuthenticationConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    @Autowired
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private UserDetailService userDetailService;


    /**
     * https://mrbird.cc/Spring-Security-SmsCode.html
     *
     * 在这个流程中，我们自定义了一个名为SmsAuthenticationFitler的过滤器来拦截短信验证码登录请求，并将手机号码封装到一个叫SmsAuthenticationToken的对象中。在Spring Security中，认证处理都需要通过AuthenticationManager来代理，所以这里我们依旧将SmsAuthenticationToken交由AuthenticationManager处理。
     *
     * 接着我们需要定义一个支持处理SmsAuthenticationToken对象的SmsAuthenticationProvider，SmsAuthenticationProvider调用UserDetailService的loadUserByUsername方法来处理认证。
     *
     * 与用户名密码认证不一样的是，这里是通过SmsAuthenticationToken中的手机号去数据库中查询是否有与之对应的用户，如果有，则将该用户信息封装到UserDetails对象中返回并将认证后的信息保存到Authentication对象中。
     *
     * 为了实现这个流程，我们需要定义SmsAuthenticationFitler、SmsAuthenticationToken和SmsAuthenticationProvider，并将这些组建组合起来添加到Spring Security中
     *
     * @param http
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        SmsAuthenticationFilter smsAuthenticationFilter = new SmsAuthenticationFilter();
        smsAuthenticationFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        smsAuthenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        smsAuthenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler);

        SmsAuthenticationProvider smsAuthenticationProvider = new SmsAuthenticationProvider();
        smsAuthenticationProvider.setUserDetailService(userDetailService);

        http.authenticationProvider(smsAuthenticationProvider)
                .addFilterAfter(smsAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    }
}
