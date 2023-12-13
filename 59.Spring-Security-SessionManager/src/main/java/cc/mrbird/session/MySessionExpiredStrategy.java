package cc.mrbird.session;

import org.springframework.http.HttpStatus;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Spring Security Session管理
 * https://mrbird.cc/Spring-Security-Session-Manage.html
 *
 * SessionInformationExpiredStrategy
 * 确定在 ConcurrentSessionFilter 中检测到过期会话时ConcurrentSessionFilter的行为
 */
@Component
public class MySessionExpiredStrategy implements SessionInformationExpiredStrategy {

    /**
     * 当检测到会话过期时的操作
     * @param event 会话信息过期事件
     * @throws IOException 输入输出异常
     * @throws ServletException 服务异常
     */
    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
        HttpServletResponse response = event.getResponse();
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write("您的账号已经在别的地方登录，当前登录已失效。如果密码遭到泄露，请立即修改密码！");
    }
}
