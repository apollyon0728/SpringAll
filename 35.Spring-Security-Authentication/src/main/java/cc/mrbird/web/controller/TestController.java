package cc.mrbird.web.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping("hello")
    public String hello() {
        return "hello spring security";
    }

    /**
     * 登录成功后，便可以使用`SecurityContextHolder.getContext().getAuthentication()`获取到`Authentication`对象信息。
     * 除了通过这种方式获取`Authentication`对象信息外，也可以使用下面这种方式
     * @param authentication
     * @return
     */
    @GetMapping("index")
    public Object index(Authentication authentication) {
        // return SecurityContextHolder.getContext().getAuthentication();
        return authentication;
    }
}
