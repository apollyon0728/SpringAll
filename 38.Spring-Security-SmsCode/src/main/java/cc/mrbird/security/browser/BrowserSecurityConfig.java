package cc.mrbird.security.browser;

import cc.mrbird.handler.MyAuthenticationFailureHandler;
import cc.mrbird.handler.MyAuthenticationSucessHandler;
import cc.mrbird.validate.code.ValidateCodeFilter;
import cc.mrbird.validate.smscode.SmsAuthenticationConfig;
import cc.mrbird.validate.smscode.SmsAuthenticationFilter;
import cc.mrbird.validate.smscode.SmsCodeFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


/**
 * `WebSecurityConfigurerAdapter` 是 Spring Security框架中用于配置 Web 安全性的一个抽象类。
 * 它提供了一种方便的方式来配置 Spring Security 的 Web 安全性，包括配置认证管理器、授权策略、安全过滤器等。
 *
 * 短信验证码
 * https://mrbird.cc/Spring-Security-SmsCode.html
 *
 * SmsAuthenticationFilter(AbstractAuthenticationProcessingFilter) -> AuthenticationManager
 *  -> SmsAuthenticationProvider(AuthenticationProvider) -> UserDetailService -> UserDetails -> Authentication
 */
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationSucessHandler authenticationSucessHandler;

    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private ValidateCodeFilter validateCodeFilter;

    @Autowired
    private SmsCodeFilter smsCodeFilter;

    @Autowired
    private SmsAuthenticationConfig smsAuthenticationConfig;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 配置HttpSecurity，添加验证码校验过滤器和短信验证码校验过滤器，设置登录相关的参数，并进行授权配置。
     *
     * @param http HttpSecurity对象
     * @throws Exception 异常信息
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // FIXME 通过addFilterBefore方法将ValidateCodeFilter验证码校验过滤器添加到了UsernamePasswordAuthenticationFilter前面
        // 如果你将validateCodeFilter和smsCodeFilter都添加为UsernamePasswordAuthenticationFilter的前置过滤器，
        // 它们将在用户名/密码认证过滤器之前执行。然而，只有通过验证的过滤器才会将请求传递给下一个过滤器或目标（例如，登录页面或受保护的资源）。
        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class) // 添加验证码校验过滤器
            .addFilterBefore(smsCodeFilter,UsernamePasswordAuthenticationFilter.class) // 添加短信验证码校验过滤器
                .formLogin() // 表单登录
                    // http.httpBasic() // HTTP Basic
                    .loginPage("/authentication/require") // 登录跳转 URL
                    .loginProcessingUrl("/login") // 处理表单登录 URL
                    .successHandler(authenticationSucessHandler) // 处理登录成功
                    .failureHandler(authenticationFailureHandler) // 处理登录失败
                .and()
                    .authorizeRequests() // 授权配置
                    .antMatchers("/authentication/require",
                            "/login.html", "/code/image","/code/sms").permitAll() // 无需认证的请求路径
                    .anyRequest()  // 所有请求
                    .authenticated() // 都需要认证
                .and()
                    .csrf().disable()
                // FIXME SecurityConfigurer的基类，允许子类仅实现它们感兴趣的方法。
                //  它还提供了使用SecurityConfigurer以及完成后获取正在配置的SecurityBuilder的访问权限的机制
                // SmsAuthenticationConfig extends SecurityConfigurerAdapter
                .apply(smsAuthenticationConfig); // 将短信验证码认证配置加到 Spring Security 中 (不光短信相关的)
    }
}

/**
 * validateCodeFilter和smsCodeFilter都继承OncePerRequestFilter，只要有一个通过就算验证通过吗？
 *
 * 在Spring Security中，addFilterBefore方法将指定的过滤器添加到给定类型的过滤器之前。
 * 这意味着，当处理请求时，这些过滤器将按照它们被添加到Spring Security过滤器链的顺序执行。
 *
 * 如果你将validateCodeFilter和smsCodeFilter都添加为UsernamePasswordAuthenticationFilter的前置过滤器，
 * 它们将在用户名/密码认证过滤器之前执行。然而，只有通过验证的过滤器才会将请求传递给下一个过滤器或目标（例如，登录页面或受保护的资源）。
 *
 * 在这种情况下，如果validateCodeFilter或smsCodeFilter中的任何一个验证成功，则请求将继续到下一个过滤器或目标。
 * 如果两个过滤器都验证成功，只有第一个验证成功的过滤器会将请求传递给下一个过滤器或目标。
 *
 * 因此，如果validateCodeFilter和smsCodeFilter都继承自OncePerRequestFilter，并且它们的验证逻辑是独立的，
 * 那么它们不会相互影响。每个过滤器将独立验证请求，并且只有第一个验证成功的过滤器会将请求传递给下一个过滤器或目标。
 *
 * 需要注意的是，如果两个过滤器的验证逻辑相互依赖或存在冲突，则可能会出现问题。在这种情况下，你可能需要重新考虑你的配置以确保逻辑的一致性。
 */