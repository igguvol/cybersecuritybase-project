In this scenario there's public page with event sign up and admin-page that requires login.
The source code can be found from https://github.com/igguvol/cybersecuritybase-project

Here the users are able only to post their name and address to sign up to the event, administrators require login and they are able to view attendees and perform some actions.
There's one admin with both username and password "admin". This by itself could be thought as a "A5-Security Misconfiguration" as administrator shouldn't have such simple default password and shouldn't be able to set that simple password, but there are worse to come.
Another bad security misconfiguration here is that while logging in requires correct username and password, anyone can directly go to /admin page without logging in.

One of the vulnerabilities is that it's possible to type in any html tags, especially <script> tag can include javascript code run on client browser and post for example users' cookies and send them to the attacker.
This can be tested:
1) send '<script>alert("hello")</script>' as a either name or address in the main page
2) view /admin page.
so "A3-Cross-Site Scripting (XSS)" is possible. 

even the worse scripts are possible to send: user could take document.cookie and post it to attackers site or somewhere public with using XMLHTTPRequest, and gain access to the admin's session
	<script	type="text/javascript">alert(document.cookie);</script>

Users are also able to use admins' commands 
	<img src="nope" onerror="document.getElementsByTagName('Form')[0].submit()" />
which indicates that "A8-Cross-Site Request Forgery (CSRF)" and "A7-Missing Function Level Access Control" are also covered here.
Even once we fix that the admin page requires authentication, "A2-Broken Authentication and Session Management" still exists


The class SecurityConfiguration in the package sec.project.config has overrided function protected void configure(HttpSecurity http)
which has two settings put on, which both make it easier to hack the site:
    http.authorizeRequests()
    	.anyRequest().permitAll();
is clearly a security misconfiguration "A5-Security Misconfiguration"
The security misconfiguration can easily be tested by going to admin-pages (http://localhost:8080/admin by default)
It can be fixed by setting framework to require authentication to certain pages, like in this case /admin
	http.authorizeRequests()
            .antMatchers("/admin").authenticated()
            .anyRequest().permitAll();

And another function call in the same function
    http.csrf().disable();
makes "A8-Cross-Site Request Forgery (CSRF)" easier, and it should be set to enable CSRF protection
    http.csrf().enable();
This doesn't prevent all problems, but this prevents some of the possible XSS attacks.

Function level access control is most critical in "deleteAll" function in AdminController, so it should be changed to 
    @RequestMapping(value = "/admin/deleteAll", method = RequestMethod.GET)
    public String deleteAll(Authentication authentication) 
    {
        if ( authentication == null )
            return "redirect:/admin";
        Account account = accountRepository.findByUsername(authentication.getName());
        if (account == null || account.getRole().matches("SUPER_ADMIN")) {
            return "redirect:/admin";
        }
        signupRepository.deleteAll();
        return "admin";
    }

"A6-Sensitive Data Exposure" vulnerability in this application is that passwords are saved in plain text, and so easier to use if attacker could get access to storage. This can be fixed by adding following methods to SecurityConfiguration class
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
which also requires that passwords are set using org.springframework.security.crypto.password.PasswordEncoder like account.setPassword(encoder.encode(password));


Also CyberSecurityBaseProjectApplication class has a function customize which sets Context setUseHttpOnly to false, so the client side script will be able to read or write the session cookie.
This vulnerability is used to get document.cookie object and send it to a web server controlled by the attacker, so it's possible to hijack users session.
Even with httpOnly flag, it's possible on some browers to get the session cookie from XMLHTTPResponse when using XMLHTTPRequest attack.
Some browsers enforce httpOnly, so if this flag doesn't help to use XSS attacks to read users cookies, like session cookie

Protecting against XSS attacks is to prevent adding any potentially vulnerable tags, which can be done several ways.
the best way is to prevent user inserting any tags in name of address fields, as names or addresses don't, as far as I know, ever contain any "larger than" or "less than" characters.
So you can just test if text for example matches to regex [^a-zA-Z\d\s'ä-öÄ-Ö\-] (may differ little bit, depending on the flavour of regex in use) and return failure without doing anything if it matches,
as this regex string matches only non-alphanumeric characters with exception of whitespaces, some umlaut characters used in finnish and hyphens.
It can be done also by replacing all special characters with equivalent html entities, where fore example that "less than" character < is converted into &lt; so it's not interpreted as html tag, but still the user sees it correctly
One of the possible libraries to do this is org.apache.commons.text with its StringEscapeUtils.escapeHtml4 function.
It can be installed into project by adding following to pom.xml dependencies
	<dependency>
	   <groupId>org.apache.commons</groupId>
	   <artifactId>commons-text</artifactId>
	   <version>1.2</version>
	</dependency>
Both of thee methods, to prevent strange input or converting it to less harmless helps to XSS, CSRF and "A1 - Injection" type of attacks.
So if no special characters are required, first method is the best, escaping string for if those are needed.
In Spring framework it's sometimes easily done, like in this case in admin.html changing address showing part of the code to
    <li th:each="item : ${list}">
        <span th:text="${item.name}+' : '+${item.address}">  </span>
    </li>
where span was earlier th:utext

After these changes, the application is secured from these attacks OWASP 10 Attacks.

