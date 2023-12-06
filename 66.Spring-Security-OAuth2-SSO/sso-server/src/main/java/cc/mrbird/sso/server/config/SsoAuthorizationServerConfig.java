package cc.mrbird.sso.server.config;

import cc.mrbird.sso.server.service.UserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * @author MrBird
 *
 * 通过使用 AuthorizationServerConfigurerAdapter，
 * 可以方便地配置授权服务器的相关设置，包括客户端详情、授权服务断点和授权服务安全配置。
 */
@Configuration
@EnableAuthorizationServer
public class SsoAuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailService userDetailService;

    /**
     * 返回一个JwtTokenStore实例，用于存储JWT令牌。
     *
     * @return JwtTokenStore实例
     */
    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    /**
     * 生成JwtAccessTokenConverter实例
     *
     * @return JwtAccessTokenConverter实例
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
        accessTokenConverter.setSigningKey("test_key");
        return accessTokenConverter;
    }

    /**
     * 配置客户端详细信息
     *
     * 配置两个客户端，分别是"app-a"和"app-b"，并设置各自的访问令牌有效期、作用域、授权类型等。
     *
     * @param clients 客户端详细信息配置器
     * @throws Exception 配置异常
     *
     *
     * 配置ClientDetailsService ，例如声明各个客户端及其属性。
     * 请注意，除非向configure(AuthorizationServerEndpointsConfigurer)提供AuthenticationManager ，
     * 否则不会启用密码授予（即使某些客户端允许）。必须声明至少一个客户端或完全形成的自定义ClientDetailsService ，
     * 否则服务器将无法启动。
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("app-a") // 客户端ID
                .secret(passwordEncoder.encode("app-a-1234")) // 客户端密钥
                .authorizedGrantTypes("refresh_token", "authorization_code") // 授权类型
                .accessTokenValiditySeconds(3600) // 访问令牌有效期（秒）
                .scopes("all") // 作用域
                .autoApprove(true) // 是否自动授权
                .redirectUris("http://127.0.0.1:9090/app1/login") // 授权回调地址

                .and()

                .withClient("app-b") // 客户端ID
                .secret(passwordEncoder.encode("app-b-1234")) // 客户端密钥
                .authorizedGrantTypes("refresh_token", "authorization_code") // 授权类型
                .accessTokenValiditySeconds(7200) // 访问令牌有效期（秒）
                .scopes("all") // 作用域
                .autoApprove(true) // 是否自动授权
                .redirectUris("http://127.0.0.1:9091/app2/login"); // 授权回调地址
    }

    /**
     * 配置授权服务器的终端点。
     * @param endpoints 授权服务器终端点配置器
     *
     * 1. `configure(AuthorizationServerEndpointsConfigurer endpoints)`:
     *                这是一个方法，接受一个`AuthorizationServerEndpointsConfigurer`类型的参数。这个参数用于配置授权服务器的端点。
     *
     * 2. `endpoints.tokenStore(jwtTokenStore())`: 这里配置了令牌存储。`jwtTokenStore()`是一个方法，
     *                 返回一个`JwtTokenStore`对象，用于存储令牌。`JwtTokenStore`是一个用于存储和检索JSON Web Tokens（JWT）的类。
     *
     * 3. `endpoints.accessTokenConverter(jwtAccessTokenConverter())`: 这里配置了访问令牌转换器。
     *                 `jwtAccessTokenConverter()`是一个方法，返回一个`JwtAccessTokenConverter`对象，用于将JWT令牌转换为授权服务器的内部表示。
     *
     * 4. `endpoints.userDetailsService(userDetailService)`: 这里配置了用户详情服务。
     *                 `userDetailService`是一个用户详情服务对象，用于根据用户信息生成用户详情。
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.tokenStore(jwtTokenStore())
                .accessTokenConverter(jwtAccessTokenConverter())
                .userDetailsService(userDetailService);
    }

    /**
     * 配置授权服务器的安全性。
     *
     * @param security 授权服务器安全配置器
     *
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security.tokenKeyAccess("isAuthenticated()"); // 获取密钥需要身份认证
    }

    /**
     * `isAuthenticated()`是一个方法，是Spring Security提供的一个过滤器方法。
     * 在Spring Security中，`isAuthenticated()`用于检查用户是否已经通过身份验证。
     * 如果用户已经通过身份验证，即用户已经成功登录，那么`isAuthenticated()`将返回`true`；否则返回`false`。
     *
     * 在您提供的代码中，`security.tokenKeyAccess("isAuthenticated()")`是配置令牌密钥的访问权限。
     * 这意味着只有经过身份验证的用户才能访问令牌密钥。
     *
     * 在Spring Security中，`isAuthenticated()`方法是在Authentication对象中实现的。
     * 当用户通过身份验证时，Spring Security会创建一个Authentication对象，其中包含用户的身份信息。
     * 在处理请求时，Spring Security会检查请求是否包含有效的Authentication对象，以确定用户是否已经通过身份验证。
     *
     * 总之，`isAuthenticated()`是一个Spring Security提供的过滤器方法，用于检查用户是否已经通过身份验证。
     * 在您提供的代码中，它被用于配置令牌密钥的访问权限，确保只有经过身份验证的用户才能访问令牌密钥。
     */
}