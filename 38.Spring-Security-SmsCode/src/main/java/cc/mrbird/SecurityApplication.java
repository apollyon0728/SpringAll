package cc.mrbird;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 在 Spring Security 5.1.4 版本中，从请求到来，通过用户名和密码进行验证的完整步骤如下：
 *
 * 1. 请求到达：用户向应用程序发送一个请求，通常是一个登录请求。
 *
 * 2. 过滤器链：请求首先经过 Spring Security 的过滤器链。这个链包括一系列的过滤器，它们按照特定的顺序执行。
 *
 * 3. 认证过滤器：在过滤器链中，有一个或多个认证过滤器。这些过滤器负责处理与认证相关的操作。
 *
 * 4. UsernamePasswordAuthenticationFilter：这是一个专门处理用户名和密码认证的过滤器。当用户提交登录表单时，该过滤器会获取用户提供的用户名和密码。
 *
 * 5. 提取认证信息：`UsernamePasswordAuthenticationFilter` 从请求中提取用户名和密码。
 *
 * 6. 认证管理器：`UsernamePasswordAuthenticationFilter` 将提取到的用户名和密码传递给 `AuthenticationManager` 进行验证。
 *
 * 7. 验证过程：`AuthenticationManager` 或其背后的 `AuthenticationProvider` 会验证用户名和密码是否匹配。这通常涉及到与数据库或其他存储系统的交互。
 *
 * 8. 返回结果：如果验证成功，`AuthenticationManager` 会返回一个包含用户信息的 `Authentication` 对象。这个对象会被存储在会话中，以便后续的请求可以访问它。
 *
 * 9. 重定向或转发：如果验证失败，`AuthenticationManager` 会抛出异常或返回一个空的 `Authentication` 对象。然后，根据配置，可能会重定向用户到登录页面或显示错误消息。
 *
 * 10. 应用逻辑继续：一旦通过了认证阶段，应用逻辑可以继续进行，例如访问受保护的资源。
 *
 * 这个过程确保了只有经过验证的用户才能访问受保护的资源，从而提供了应用程序的安全性。
 */
@SpringBootApplication
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }
}
