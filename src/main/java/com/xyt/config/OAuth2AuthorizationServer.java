package com.xyt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * 授权服务器
 */
@Configuration
@EnableAuthorizationServer // 此注解开启授权认证！！！
public class OAuth2AuthorizationServer extends AuthorizationServerConfigurerAdapter {

    /**
     * 注入AuthenticationManager ，密码模式用到
     */
    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 对Jwt签名时，增加一个密钥
     * JwtAccessTokenConverter：对Jwt来进行编码以及解码的类
     */
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("test-secret");
        return converter;
    }

    /**
     * 设置token 由Jwt产生，不使用默认的透明令牌
     */
    @Bean
    public JwtTokenStore jwtTokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
                .authenticationManager(authenticationManager)
                .tokenStore(jwtTokenStore())
                .accessTokenConverter(accessTokenConverter());
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("clientapp")//给用户颁发的appId
                .secret("123456")   //给用户颁发的appSecret
                .scopes("read")
                //设置支持[密码模式、授权码模式、token刷新]
                .authorizedGrantTypes(
                        "password",
                        "client_credentials",
                        "authorization_code",
                        "refresh_token")
                .accessTokenValiditySeconds(3600) // 访问令牌(accessToken)有效期
                .refreshTokenValiditySeconds(3600); // 刷新令牌(refreshToken)有效期
    }
}
