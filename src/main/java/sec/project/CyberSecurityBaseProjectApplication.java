package sec.project;

import org.apache.catalina.Context;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.context.embedded.tomcat.TomcatContextCustomizer;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import sec.project.domain.Account;
import sec.project.repository.AccountRepository;

@SpringBootApplication
public class CyberSecurityBaseProjectApplication implements EmbeddedServletContainerCustomizer
{
    public static void main(String[] args) throws Throwable {
        SpringApplication.run(CyberSecurityBaseProjectApplication.class);
    }
    
    @Autowired
    private AccountRepository accountRepository;
    
    @Override
    public void customize(ConfigurableEmbeddedServletContainer cesc) {
        ((TomcatEmbeddedServletContainerFactory) cesc).addContextCustomizers(new TomcatContextCustomizer() {
            @Override
            public void customize(Context cntxt) {
                cntxt.setUseHttpOnly(false);
                
                Account account = new Account();
                account.setUsername( "admin" );
                account.setPassword( "admin" );
                accountRepository.save( account );
                
                
            }
            
        });
    }
    
    
}
