package cc.mrbird.security.browser;

import cc.mrbird.handler.MyAuthenticationFailureHandler;
import cc.mrbird.handler.MyAuthenticationSucessHandler;
import cc.mrbird.session.MySessionExpiredStrategy;
import cc.mrbird.validate.code.ValidateCodeFilter;
import cc.mrbird.validate.smscode.SmsAuthenticationConfig;
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
 * Spring Security Session管理
 *
 * https://mrbird.cc/Spring-Security-Session-Manage.html
 */
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationSucessHandler authenticationSuccessHandler;

    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private ValidateCodeFilter validateCodeFilter;

    @Autowired
    private SmsCodeFilter smsCodeFilter;

    @Autowired
    private SmsAuthenticationConfig smsAuthenticationConfig;

    /**
     * Session在并发下失效后的处理策略，这里为我们自定义的策略MySessionExpiredStrategy
     */
    @Autowired
    private MySessionExpiredStrategy sessionExpiredStrategy;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * 配置HttpSecurity
     * Session并发控制可以控制一个账号同一时刻最多能登录多少个。我们在Spring Security配置中继续添加Session相关配置:
     *
     * @param http HttpSecurity对象
     * @throws Exception 异常
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class) // 添加验证码校验过滤器
            .addFilterBefore(smsCodeFilter,UsernamePasswordAuthenticationFilter.class) // 添加短信验证码校验过滤器
                .formLogin() // 表单登录
                    // http.httpBasic() // HTTP Basic
                    .loginPage("/authentication/require") // 登录跳转 URL
                    .loginProcessingUrl("/login") // 处理表单登录 URL
                    .successHandler(authenticationSuccessHandler) // 处理登录成功
                    .failureHandler(authenticationFailureHandler) // 处理登录失败
                .and()
                    .authorizeRequests() // 授权配置
                    .antMatchers("/authentication/require",
                            "/login.html", "/code/image","/code/sms","/session/invalid").permitAll() // 无需认证的请求路径
                    .anyRequest()  // 所有请求
                    .authenticated() // 都需要认证
                .and()
                // FIXME sessionManagement配置的时候将 ConcurrentSessionFilter 加入，实现用户会话的并发控制
                    .sessionManagement() // 添加 Session管理器
                    .invalidSessionUrl("/session/invalid") // Session失效后跳转到这个链接
                // FIXME maximumSessions配置了最大Session并发数量为1个，例如如果mrbird这个账户登录后，
                //  在另一个客户端也使用mrbird账户登录，那么第一个使用mrbird登录的账户将会失效，类似于一个先入先出队列。
                    .maximumSessions(1)
                    .maxSessionsPreventsLogin(true)
                // FIXME expiredSessionStrategy配置了Session在并发下失效后的处理策略，这里为我们自定义的策略MySessionExpiredStrategy
                    .expiredSessionStrategy(sessionExpiredStrategy)
                .and()
                .and()
                // FIXME CSRF（跨站请求伪造）是一种常见的网络攻击方式，攻击者通过伪造合法用户的请求，利用用户的身份进行非法操作。
                //  为了防范 CSRF 攻击，Spring Security 提供了默认的 CSRF 防护措施。
                //  当开发测试环境或者调试过程中，需要关闭 CSRF 防护以方便测试和调试。在这种情况下，可以使用 .csrf().disable() 来禁用 CSRF 防护
                    .csrf().disable()
                // FIXME 将短信验证码认证配置加到 Spring Security 中
                .apply(smsAuthenticationConfig);
    }
}

/**
 * .sessionManagement() 设置了 SessionManagementConfigurer, 其包含了 “ConcurrentSessionFilter”，当配置中设置了
 *
 * “.maximumSessions()”，则开启了 “ConcurrentSessionFilter”，可以看上面 SessionManagementConfigurer 知识点和部分源码
 *
 * SessionManagementConfigurer 中源码
 * private boolean isConcurrentSessionControlEnabled() {
 * 		return this.maximumSessions != null;
 *        }
 *
 *
 */













