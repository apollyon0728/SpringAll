package cc.mrbird.validate.smscode;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

import java.util.Collection;

/**
 * 短信验证码登录
 * https://mrbird.cc/Spring-Security-SmsCode.html
 *
 *
 * AbstractAuthenticationToken是一个抽象类，用于表示一种身份验证令牌（Authentication Token）。
 * 它提供了身份验证令牌的一些通用属性和方法，可以被具体实现以表示不同类型的身份验证令牌
 *
 * AbstractAuthenticationToken 是用于存储认证信息的抽象类。
 *
 * 查看UsernamePasswordAuthenticationToken的源码，
 * 将其复制出来重命名为SmsAuthenticationToken，并稍作修改，修改后的代码如下所示：
 */
public class SmsAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final Object principal;

    /**
     * 构造方法，用于创建一个短信认证令牌
     * @param mobile 手机号码
     * @return SmsAuthenticationToken 短信认证令牌
     */
    public SmsAuthenticationToken(String mobile) {
        super(null);
        this.principal = mobile;
        setAuthenticated(false);
    }

    /**
     * SmsAuthenticationToken的构造方法，用于创建一个SMS认证令牌对象。
     * @param principal 认证令牌的主体对象
     * @param authorities 认证令牌的权限集合
     */
    public SmsAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        // FIXME 使用提供的权限数组创建一个令牌。
        // 参数： authorities – 此身份验证对象所代表的主体的GrantedAuthority的集合。
        super(authorities);

        this.principal = principal;

        // FIXME must use super, as we override
        super.setAuthenticated(true);
    }

    /**
     * 获取凭证的方法
     *
     * @return 凭证对象，此处返回null
     */
    @Override
    public Object getCredentials() {
        return null;
    }

    /**
     * 获取主体对象
     *
     * @return 主体对象
     */
    public Object getPrincipal() {
        return this.principal;
    }

    /**
     * 设置身份验证状态
     * @param isAuthenticated 身份验证状态，true表示已验证，false表示未验证
     * @throws IllegalArgumentException 如果要将令牌设置为受信任状态，则抛出IllegalArgumentException异常
     */

    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
    }


    /**
     * 覆盖父类的方法，用于擦除凭证信息。
     */
    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
    }
}

/**
 * **Spring Security中的AbstractAuthenticationToken是一个抽象类，用于表示一种身份验证令牌（Authentication Token）。
 * 它提供了身份验证令牌的一些通用属性和方法，可以被具体实现以表示不同类型的身份验证令牌。**
 *
 *
 * **AbstractAuthenticationToken包含以下主要属性和方法：**
 *
 *    1.Principal：表示身份验证令牌所关联的用户或实体。在AbstractAuthenticationToken中，Principal是一个接口，需要具体实现类来提供用户信息。
 *    2.Credentials：表示身份验证令牌的凭证信息，例如密码或令牌。
 *    3.AdditionalInformation：用于存储与身份验证令牌相关的其他额外信息。
 *    4.Authenticated：表示身份验证是否成功。这是一个布尔值，通常在具体实现中进行设置。
 *    5.getPrincipal()和setPrincipal()：获取和设置Principal的方法。
 *    6.getCredentials()和setCredentials()：获取和设置Credentials的方法。
 *    7.getAdditionalInformation()和setAdditionalInformation()：获取和设置AdditionalInformation的方法。
 *    8.isAuthenticated()：返回身份验证是否成功的方法。具体实现通常会根据是否成功进行身份验证来设置Authenticated属性。
 *
 * 通过继承AbstractAuthenticationToken，您可以创建特定类型的身份验证令牌，并实现其中的方法来提供具体的用户信息和凭证信息。
 * 然后，您可以将这些令牌传递给Spring Security的身份验证管理器进行验证，并根据验证结果来决定是否允许用户访问受保护的资源。
 */















