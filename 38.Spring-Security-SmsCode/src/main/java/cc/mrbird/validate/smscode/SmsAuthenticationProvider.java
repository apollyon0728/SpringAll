package cc.mrbird.validate.smscode;

import cc.mrbird.security.browser.UserDetailService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * 该类需要实现AuthenticationProvider的两个抽象方法
 *
 * SmsAuthenticationFilter(AbstractAuthenticationProcessingFilter) -> AuthenticationManager
 *  -> SmsAuthenticationProvider(AuthenticationProvider) -> UserDetailService -> UserDetails -> Authentication
 */
public class SmsAuthenticationProvider implements AuthenticationProvider {

    private UserDetailService userDetailService;

    /**
     * 覆盖父类的方法，用于进行身份验证
     *
     * authenticate方法用于编写具体的身份认证逻辑。
     *  在authenticate方法中，我们从SmsAuthenticationToken中取出了手机号信息，
     *  并调用了UserDetailService的loadUserByUsername方法。
     *  该方法在用户名密码类型的认证中，主要逻辑是通过用户名查询用户信息，如果存在该用户并且密码一致则认证成功；
     *  而在短信验证码认证的过程中，该方法需要通过手机号去查询用户，如果存在该用户则认证通过。
     *
     *  认证通过后接着调用SmsAuthenticationToken的SmsAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities)构造函数构造一个认证通过的Token，包含了用户信息和用户权限。
     *
     *  你可能会问，为什么这一步没有进行短信验证码的校验呢？实际上短信验证码的校验是在SmsAuthenticationFilter之前完成的，
     *  即只有当短信验证码正确以后才开始走认证的流程。所以接下来我们需要定一个过滤器来校验短信验证码的正确性。
     *
     * @param authentication 身份验证对象
     * @return 身份验证结果
     * @throws AuthenticationException 身份验证异常
     */

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        SmsAuthenticationToken authenticationToken = (SmsAuthenticationToken) authentication;
        UserDetails userDetails = userDetailService.loadUserByUsername((String) authenticationToken.getPrincipal());

        if (userDetails == null)
            throw new InternalAuthenticationServiceException("未找到与该手机号对应的用户");

        SmsAuthenticationToken authenticationResult = new SmsAuthenticationToken(userDetails, userDetails.getAuthorities());

        authenticationResult.setDetails(authenticationToken.getDetails());

        return authenticationResult;
    }

    /**
     * 判断是否支持指定的类。
     *
     * supports方法指定了支持处理的Token类型为SmsAuthenticationToken，
     *
     * @param aClass 要判断的类
     * @return 如果指定的类是 SmsAuthenticationToken 类或其子类，则返回 true；否则返回 false
     */
    @Override
    public boolean supports(Class<?> aClass) {
        return SmsAuthenticationToken.class.isAssignableFrom(aClass);
    }

    /**
     * 获取UserDetailService对象
     *
     * @return UserDetailService对象
     */
    public UserDetailService getUserDetailService() {
        return userDetailService;
    }

    /**
     * 设置用户详细信息服务
     *
     * @param userDetailService 用户详细信息服务对象
     */
    public void setUserDetailService(UserDetailService userDetailService) {
        this.userDetailService = userDetailService;
    }
}
