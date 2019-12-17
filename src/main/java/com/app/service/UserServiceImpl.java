package com.app.service;

import com.app.model.Role;
import com.app.model.User;
import com.app.repository.RoleRespository;
import com.app.repository.UserRepository;
import com.app.util.ReCapchaUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;


@Service("userService")
public class UserServiceImpl implements UserService {

 @Qualifier("userRepository")
 @Autowired
 private UserRepository userRepository;
 
 @Autowired
 private RoleRespository roleRespository;
 
 @Autowired
 private BCryptPasswordEncoder bCryptPasswordEncoder;


 @Autowired
 private RestTemplateBuilder restTemplateBuilder;



    @Value("${google.reCapcha.key.secret}")
    private String capchaSecret;

    private static final String GOOGLE_RECAPTCHA_VERIFY_URL =
         "https://www.google.com/recaptcha/api/siteverify";

    @Override
    public String verifyCapcha(String captchaResponse){
     Map<String, String> body = new HashMap<>();
     body.put("secret", capchaSecret);
     body.put("response", captchaResponse);

     ResponseEntity<Map> recaptchaResponseEntity = restTemplateBuilder.build()
             .postForEntity(GOOGLE_RECAPTCHA_VERIFY_URL+
                     "?secret={secret}&response={response}", body, Map.class, body);


     Map<String, Object> responseBody = recaptchaResponseEntity.getBody();
     boolean recaptchaSucess = (Boolean)responseBody.get("success");

     if ( !recaptchaSucess) {
      List<String> errorCodes = (List)responseBody.get("error-codes");
      String errorMessage = errorCodes.stream()
              .map(s -> ReCapchaUtil.RECAPTCHA_ERROR_CODE.get(s))
              .collect(Collectors.joining(", "));
      return errorMessage;
     }else return StringUtils.EMPTY;

    }


 @Override
 public User findUserByEmail(String email) {
  return userRepository.findByEmail(email);
 }

 @Override
 public void saveUser(User user) {
  user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
  user.setActive(1);
  Role userRole = roleRespository.findByRole("USER");
  user.setRoles(new HashSet<Role>(Arrays.asList(userRole)));
  userRepository.save(user);
 }

}
