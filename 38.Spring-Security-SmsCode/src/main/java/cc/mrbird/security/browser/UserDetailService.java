package cc.mrbird.security.browser;

import cc.mrbird.domain.MyUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * UserDetailService`接口是用于从存储中提取用户详细信息的服务。
 * 它主要负责从数据库或其他存储介质中加载用户的详细信息，并将其封装到`UserDetails`对象中。
 * `UserDetails`对象包含用户的基本信息，如用户名、密码、角色等。
 *
 * `UserDetailsService`接口只有一个方法，即`loadUserByUsername`，
 *   该方法接受一个用户名作为参数，并返回一个`UserDetails`对象。
 *   这个方法通常会被Spring Security的认证管理器调用，以便在用户进行身份验证时获取用户的详细信息。
 */
@Configuration
public class UserDetailService implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;


    /**
     * 根据用户名定位用户。
     *
     * 在实际实现中，搜索可能区分大小写，也可能不区分大小写，具体取决于实现实例的配置方式。
     * 在这种情况下，返回的UserDetails对象可能具有与实际请求的用户名不同的情况。
     *
     * 参数： username – 标识需要其数据的用户的用户名。
     * 返回： 完全填充的用户记录（绝不为null ）
     *
     * @param username the username identifying the user whose data is required.
     *
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 模拟一个用户，替代数据库获取逻辑
        MyUser user = new MyUser();
        user.setUserName(username);
        user.setPassword(this.passwordEncoder.encode("123"));

        // 输出加密后的密码
        System.out.println(user.getPassword());

        /**
         * 使用org.springframework.security.authentication.dao.DaoAuthenticationProvider所需的详细信息构造User 。
         *
         * 参数：
         * username – 提供给DaoAuthenticationProvider用户名
         * password – 应提供给DaoAuthenticationProvider密码
         * enabled – 如果用户已启用，则设置为true
         * accountNonExpired – 如果帐户尚未过期，则设置为true
         * credentialsNonExpired – 如果凭据尚未过期，则设置为true
         * accountNonLocked – 如果帐户未锁定，则设置为true
         * authorities – 如果调用者提供了正确的用户名和密码并且用户已启用，则应授予调用者权限。不为空。
         */
        return new User(username, user.getPassword(), user.isEnabled(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isAccountNonLocked(),
                // authorities – 如果调用者提供了正确的用户名和密码并且用户已启用，则应授予调用者权限。不为空。
                AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
