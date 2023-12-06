package cc.mrbird.security.browser;

import cc.mrbird.handler.MyAuthenticationFailureHandler;
import cc.mrbird.handler.MyAuthenticationSucessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


/**
 * Spring Security自定义用户认证
 * https://mrbird.cc/Spring-Security-Authentication.html
 */
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationSucessHandler authenticationSuccessHandler;

    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * `.loginPage("/authentication/require")`指定了跳转到登录页面的请求URL，也可以直接配置一个静态文件的路径(/login.html)
     * `.loginProcessingUrl("/login")`对应登录页面form表单的`action="/login"`，
     * `.antMatchers("/login.html").permitAll()`表示跳转到登录页面的请求不被拦截，否则会进入无限循环。
     *
     * @param http the {@link HttpSecurity} to modify
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() // 表单登录
                // http.httpBasic() // HTTP Basic
                .loginPage("/authentication/require") // 登录跳转 URL
                .loginProcessingUrl("/login") // 处理表单登录 URL
                .successHandler(authenticationSuccessHandler) // 处理登录成功（这里是自定义的）
                .failureHandler(authenticationFailureHandler) // 处理登录失败（这里是自定义的）
                .and()
                .authorizeRequests() // 授权配置
                .antMatchers("/authentication/require", "/login.html").permitAll() // 登录跳转 URL 无需认证
                .anyRequest()  // 所有请求
                .authenticated() // 都需要认证
                .and().csrf().disable();
    }
}
