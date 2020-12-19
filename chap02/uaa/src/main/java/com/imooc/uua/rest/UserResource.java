package com.imooc.uua.rest;

import com.imooc.uua.domain.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;

/**
 * @author pengfei.zhao
 * @date 2020/12/19 12:43
 */
@RestController
@RequestMapping("/api")
public class UserResource {

    @GetMapping("/me")
    public User getProfile(){
        return User.builder()
                .name("张三")
                .username("zhangsan")
                .roles(Collections.singletonList("USER"))
                .build();
    }
}
