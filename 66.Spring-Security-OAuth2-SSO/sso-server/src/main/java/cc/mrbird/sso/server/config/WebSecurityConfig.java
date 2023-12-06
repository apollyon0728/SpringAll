package cc.mrbird.sso.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author MrBird
 *
 * WebSecurityConfigurerAdapter是由Spring Security提供的Web应用安全配置的适配器
 *
 * https://mrbird.cc/Spring-Boot&Spring-Security.html
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
        // `BCryptPasswordEncoder`是Spring Security提供的一个实现方法
        // 它对相同的密码进行加密后可以生成不同的结果
        return new BCryptPasswordEncoder();
    }

    /**
     * 配置HTTP安全性
     *
     * Spring Security提供了这种链式的方法调用。配置指定了认证方式为表单登录，并且所有请求都需要进行认证
     *
     * @param http HttpSecurity对象，用于配置HTTP安全性
     * @throws Exception 配置异常
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 配置表单登录 (表单方式）
        http.formLogin()
                .and()
                // 配置请求授权
                .authorizeRequests()
                .anyRequest()
                .authenticated();

    }
}
