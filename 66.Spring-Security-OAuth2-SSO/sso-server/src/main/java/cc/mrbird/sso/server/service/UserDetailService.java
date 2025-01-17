package cc.mrbird.sso.server.service;

import cc.mrbird.sso.server.domain.MyUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author MrBird
 *
 * 加载用户特定数据的核心接口。
 * 它在整个框架中用作用户 DAO，并且是DaoAuthenticationProvider使用的策略。
 * 该接口仅需要一种只读方法，从而简化了对新数据访问策略的支持
 */
@Configuration
public class UserDetailService implements UserDetailsService {

    /**
     * 注入了`PasswordEncoder`对象，该对象用于密码加密，注入前需要手动配置。
     * 本例是在`WebSecurityConfig`中配置它
     */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 根据用户名加载用户详情。
     *
     * 在实际实现中，搜索可能区分大小写，也可能不区分大小写，具体取决于实现实例的配置方式。
     * 在这种情况下，返回的UserDetails对象可能具有与实际请求的用户名不同的情况
     *
     * @param username 用户名
     * @return 响应的用户详情
     * @throws UsernameNotFoundException 如果用户名不存在
     *
     * 翻译：
     * 使用org.springframework.security.authentication.dao.DaoAuthenticationProvider所需的详细信息构造User 。
     * 参数：
     * username – 提供给DaoAuthenticationProvider用户名
     * password – 应提供给DaoAuthenticationProvider密码
     * enabled – 如果用户已启用，则设置为true
     * accountNonExpired – 如果帐户尚未过期，则设置为true
     * credentialsNonExpired – 如果凭据尚未过期，则设置为true
     * accountNonLocked – 如果帐户未锁定，则设置为true
     * authorities – 如果调用者提供了正确的用户名和密码并且用户已启用，则应授予调用者权限。不为空。
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // FIXME ：my: 实际的生产环境，从数据库中或其他来源读取用户信息进行设置

        MyUser user = new MyUser();
        user.setUserName(username);
        user.setPassword(this.passwordEncoder.encode("123456"));
        return new User(username, user.getPassword(), user.isEnabled(),
                user.isAccountNonExpired(), // 如果帐户尚未过期，则设置为true
                user.isCredentialsNonExpired(), // 如果凭据尚未过期，则设置为true
                user.isAccountNonLocked(), // 如果帐户未锁定，则设置为true
                AuthorityUtils.commaSeparatedStringToAuthorityList("user:add")); // 如果调用者提供了正确的用户名和密码并且用户已启用，则应授予调用者权限。不为空
    }

}