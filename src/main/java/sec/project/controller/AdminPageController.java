package sec.project.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import sec.project.domain.Account;
import sec.project.domain.Signup;
import sec.project.repository.AccountRepository;
import sec.project.repository.SignupRepository;

@Controller
public class AdminPageController {
    
    @Autowired
    private SignupRepository signupRepository;
    @Autowired
    private AccountRepository accountRepository;

  
    @RequestMapping(value = "/admin", method = RequestMethod.GET)
    public String getIndex(Model model) {
        model.addAttribute("list", signupRepository.findAll());
        return "admin";
    }

    @RequestMapping(value = "/admin", method = RequestMethod.POST)
    public String adminLogin(@RequestParam String username, @RequestParam String password) {
        Account account = accountRepository.findByUsername(username);
        if ( account.getPassword().equals(password) )
            return "admin";
        return "redirect:/";
    }

    @RequestMapping(value = "/admin/deleteAll", method = RequestMethod.POST)
    public String deleteAll(Authentication authentication) 
    {
        signupRepository.deleteAll();
        return "redirect:/admin";
    }
    
}
