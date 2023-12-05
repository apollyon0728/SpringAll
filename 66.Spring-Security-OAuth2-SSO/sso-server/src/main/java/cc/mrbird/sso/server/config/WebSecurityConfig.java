package cc.mrbird.sso.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author MrBird
 */
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 返回一个{@code PasswordEncoder}实例，用于对密码进行加密。
     *
     * @return 一个{@code PasswordEncoder}实例，用于对密码进行加密。
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 配置HTTP安全性
     *
     * @param http HttpSecurity对象，用于配置HTTP安全性
     * @throws Exception 配置异常
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 配置表单登录
        http.formLogin()
                .and()
                // 配置请求授权
                .authorizeRequests()
                .anyRequest()
                .authenticated();
    }
}
