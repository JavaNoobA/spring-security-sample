package com.imooc.uua.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * @author pengfei.zhao
 * @date 2020/12/19 12:42
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {
    private String username;

    private String name;

    private List<String> roles;
}
