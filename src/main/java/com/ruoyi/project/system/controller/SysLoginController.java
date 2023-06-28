package com.ruoyi.project.system.controller;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.List;
import java.util.Set;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.common.utils.http.HttpUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import com.ruoyi.common.constant.Constants;
import com.ruoyi.common.utils.SecurityUtils;
import com.ruoyi.framework.security.LoginBody;
import com.ruoyi.framework.security.service.SysLoginService;
import com.ruoyi.framework.security.service.SysPermissionService;
import com.ruoyi.framework.web.domain.AjaxResult;
import com.ruoyi.project.system.domain.SysMenu;
import com.ruoyi.project.system.domain.SysUser;
import com.ruoyi.project.system.service.ISysMenuService;

/**
 * 登录验证
 * 
 * @author ruoyi
 */
@RestController
public class SysLoginController
{
    @Autowired
    private SysLoginService loginService;

    @Autowired
    private ISysMenuService menuService;

    @Autowired
    private SysPermissionService permissionService;

    /**
     * 登录方法
     * 
     * @param loginBody 登录信息
     * @return 结果
     */
    @PostMapping("/login")
    public AjaxResult login(@RequestBody LoginBody loginBody)
    {
        String pwd = "admin123";
        AjaxResult ajax = AjaxResult.success();
        // 生成令牌
        String token = loginService.login(loginBody.getUsername(), pwd, loginBody.getCode(),loginBody.getUuid());
        ajax.put(Constants.TOKEN, token);
        return ajax;
    }

    @Value("${sms.sendYzmUrl}")
    public String sendYzmUrl;

    private static final Logger log = LoggerFactory.getLogger(SysLoginController.class);
    /**
     * 发送短信验证码
     */
    @PostMapping("/sendYzm")
    @ResponseBody
    public AjaxResult sendYzm(String phonenumber) {
        log.info("phonenumber_______:"+phonenumber);
        AjaxResult ajax = AjaxResult.error();
        String template = "您的验证码为：${yzm}，请勿告知他人。如非您本人操作，请忽略本短信。";
        String EncoderContent = "";
        try {
            EncoderContent = URLEncoder.encode(template, "GBK");
            EncoderContent = URLEncoder.encode(EncoderContent, "GBK");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        log.info("sendYzmUrl_______:"+sendYzmUrl);
        String yzmSeqjson = HttpUtils.sendPost(sendYzmUrl + phonenumber + "/" + EncoderContent, "");
//        String yzmSeqjson = "{\"code\":\"5\",\"msg\":10}";
        if(StringUtils.isEmpty(yzmSeqjson)){
            ajax.put("code","99");
            ajax.put("msg","获取验证码失败");
            return ajax;
        }
        ajax = AjaxResult.success();
        JSONObject json = JSON.parseObject(yzmSeqjson);
//        ajax.put("code",json.getString("code"));
        ajax.put("msg",json.getString("msg"));
        return ajax;
    }

    /**
     * 获取用户信息
     * 
     * @return 用户信息
     */
    @GetMapping("getInfo")
    public AjaxResult getInfo()
    {
        SysUser user = SecurityUtils.getLoginUser().getUser();
        // 角色集合
        Set<String> roles = permissionService.getRolePermission(user);
        // 权限集合
        Set<String> permissions = permissionService.getMenuPermission(user);
        AjaxResult ajax = AjaxResult.success();
        ajax.put("user", user);
        ajax.put("roles", roles);
        ajax.put("permissions", permissions);
        return ajax;
    }

    /**
     * 获取路由信息
     * 
     * @return 路由信息
     */
    @GetMapping("getRouters")
    public AjaxResult getRouters()
    {
        Long userId = SecurityUtils.getUserId();
        List<SysMenu> menus = menuService.selectMenuTreeByUserId(userId);
        return AjaxResult.success(menuService.buildMenus(menus));
    }
}
