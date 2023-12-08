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
 */
@Configuration
public class UserDetailService implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;


    /**
     * `UserDetailsService`接口只有一个方法，即`loadUserByUsername`，
     * 该方法接受一个用户名作为参数，并返回一个`UserDetails`对象。
     * 这个方法通常会被Spring Security的认证管理器调用，以便在用户进行身份验证时获取用户的详细信息。
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
        user.setPassword(this.passwordEncoder.encode("123456"));
        // 输出加密后的密码
        System.out.println(user.getPassword());

        return new User(username, user.getPassword(), user.isEnabled(),
                user.isAccountNonExpired(), user.isCredentialsNonExpired(),
                user.isAccountNonLocked(), AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
