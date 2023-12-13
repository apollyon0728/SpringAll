package cc.mrbird;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


/**
 * Spring Security Session管理
 * https://mrbird.cc/Spring-Security-Session-Manage.html
 *
 * 在实际开发中，发现Session并发控制只对Spring Security默认的登录方式——账号密码登录有效，
 * 而像短信验证码登录，社交账号登录并不生效，解决方案可以参考我的开源项目https://github.com/wuyouzhuguli/FEBS-Security
 */
@SpringBootApplication
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }
}
