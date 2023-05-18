package kz.bitlab.springsecuritytesting.controllers;

import kz.bitlab.springsecuritytesting.entities.Users;
import kz.bitlab.springsecuritytesting.services.MyUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HomeController {
    @Autowired
    private MyUserService userService;
    @GetMapping(value="/login")
    public String openLogin(){
        return "login";
    }
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN','ROLE_USER')")
    @GetMapping(value="/home")
    public String openHome(){
        return "home";
    }
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN','ROLE_USER')")
    @GetMapping(value="/profile")
    public String openProfile(){
        return "profile";
   }
    @GetMapping(value="/register")
    public String openRegister(){
        return "register";
    }
    @PostMapping(value="/register")
    public String registerPost(@RequestParam(name="user-full-name") String fullName,
                               @RequestParam(name="user-email") String email,
                               @RequestParam(name="user-password") String password,
                               @RequestParam(name="user-re-password") String rePassword){
        String redirect = "";
        String check = userService.registerUser(fullName,email,password,rePassword);
        if(check.equals("successRegister")){
            redirect = "/register?success";
        }
        else if(check.equals("userExist")){
            redirect = "/register?userExist";
        }
        else{
            redirect = "/register?passwordNotMatch";
        }
        return "redirect:" + redirect;
    }
    @GetMapping(value="/403")
    public String openAccessDenied(){
        return "403";
    }
    @PreAuthorize("hasAnyAuthority('ROLE_USER','ROLE_ADMIN')")
    @GetMapping(value="/change-password")
    public String openChangePassword(){
        return "change-password";
    }
    @PostMapping(value="/change-password")
    public String changePasswordPost(@RequestParam(name="user-email") String email,
                                     @RequestParam(name="user-old-password") String oldPassword,
                                     @RequestParam(name="user-new-password") String newPassword,
                                     @RequestParam(name="user-re-new-password") String newRePassword){
        String redirect = "";
        String check = userService.changePassword(email,oldPassword,newPassword,newRePassword);
        if(check.equals("userNotFound")){
            redirect = "/change-password?" + check;
        }
        else if(check.equals("oldPasswordIncorrect")){
            redirect = "/change-password?" + check;
        }
        else if(check.equals("newPasswordsNotMatches")){
            redirect = "/change-password?" + check;
        }
        else{
            redirect = "/change-password?" + check;
        }
        return "redirect:" + redirect;
    }
}
