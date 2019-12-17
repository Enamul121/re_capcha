package com.app.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {


	 @Autowired
	 private BCryptPasswordEncoder bCryptPasswordEncoder;
	 
	 @Autowired
	 private DataSource dataSource;
	 
	 private final String USERS_QUERY = "select email, password, active from user where email=?";
	 private final String ROLES_QUERY = "select u.email, r.role from user u inner join user_role ur on (u.id = ur.user_id) inner join role r on (ur.role_id=r.role_id) where u.email=?";

	 @Override
	 protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	  auth.jdbcAuthentication()
	   .usersByUsernameQuery(USERS_QUERY)
	   .authoritiesByUsernameQuery(ROLES_QUERY)
	   .dataSource(dataSource)
	   .passwordEncoder(bCryptPasswordEncoder);
	 }

	 @Override
	 protected void configure(HttpSecurity http) throws Exception {



		 http.authorizeRequests()
	   .antMatchers("/","/resources/**", "/css/**", "/images/**", "/fonts/**", "/scripts/**").permitAll()
		.antMatchers("/logout").permitAll()
	   .antMatchers("/login","/signup").permitAll()
	   .antMatchers("/home/**").hasAnyAuthority("ADMIN","USER").anyRequest()
	   .authenticated().and() .csrf().disable()
	   .formLogin().loginPage("/login").failureUrl("/login?error=true")
	   .defaultSuccessUrl("/home")
	   .usernameParameter("email")
	   .passwordParameter("password")
	   .and().logout()
				 .clearAuthentication(true)
				 .logoutUrl("/logout")
				 .logoutSuccessUrl("/")
				 .deleteCookies("JSESSIONID")
				 .invalidateHttpSession(true);
	 }
	 



	@Override
	public void configure(WebSecurity web) throws Exception {
		 web
			.ignoring()
			.antMatchers("/resources/**","/css/**", "/images/**", "/fonts/**"); // #3
	}




}
