package cc.mrbird.validate.smscode;

import cc.mrbird.security.browser.UserDetailService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * AuthenticationProvider`的具体实现通常需要实现`authenticate`方法，
 * 该方法接收一个`Authentication`对象作为参数，并返回一个`Authentication`对象，表示身份验证的结果。
 * 在实现自定义的身份验证逻辑时，可以创建一个继承自`AuthenticationProvider`的类，并重写`authenticate`方法。
 * 该类需要实现AuthenticationProvider的两个抽象方法
 *
 * SmsAuthenticationFilter(AbstractAuthenticationProcessingFilter) -> AuthenticationManager
 *  -> SmsAuthenticationProvider(AuthenticationProvider) -> UserDetailService -> UserDetails -> Authentication
 */
public class SmsAuthenticationProvider implements AuthenticationProvider {

    private UserDetailService userDetailService;

    /**
     * 覆盖父类的方法，完善 Authentication 后面用于进行身份验证 ？
     *
     * MY：该方法并没有实际的进行验证，应该是完善 Authentication
     *
     * 使用与AuthenticationManager.authenticate(Authentication)相同的合约执行身份验证。
     *
     * 参数： authentication – 身份验证请求对象。
     * 返回： 一个经过完全身份验证的对象，包括凭据。如果AuthenticationProvider无法支持对传递的Authentication对象进行身份验证，则可能返回null 。在这种情况下，将尝试下一个支持所提供的Authentication类AuthenticationProvider
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
     *  即只有当短信验证码正确以后才开始走认证的流程。
     *
     * @param authentication 身份验证对象
     * @return 身份验证结果
     * @throws AuthenticationException 身份验证异常
     */

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        SmsAuthenticationToken authenticationToken = (SmsAuthenticationToken) authentication;

        // FIXME 根据用户名定位用户。
        UserDetails userDetails = userDetailService.loadUserByUsername((String) authenticationToken.getPrincipal());

        if (userDetails == null)
            throw new InternalAuthenticationServiceException("未找到与该手机号对应的用户");

        // FIXME userDetails.getAuthorities() 返回授予用户的权限。无法返回 null
        SmsAuthenticationToken authenticationResult = new SmsAuthenticationToken(userDetails, userDetails.getAuthorities());

        // FIXME `details` 属性可以用于存储与认证请求相关的其他信息，例如请求的来源、请求的参数等。
        //  这些信息对于后续的认证处理可能非常有用，例如在处理跨域请求、记录日志或进行其他自定义处理时。
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
        /**
         * 确定此Class对象表示的类或接口是否与指定Class参数表示的类或接口相同，或者是其超类或超接口。
         * 如果是则返回true ；否则返回false 。
         * 如果此Class对象表示基本类型，且指定的Class参数正是此Class对象，则此方法返回true ；否则返回false 。
         *
         * 具体来说，此方法测试是否可以通过标识转换或扩大引用转换将指定Class参数表示的类型转换为此Class对象表示的类型
         */
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
