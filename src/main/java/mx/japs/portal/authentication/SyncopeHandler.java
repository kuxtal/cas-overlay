package mx.japs.portal.authentication;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.login.FailedLoginException;

import org.apache.syncope.client.SyncopeClient;
import org.apache.syncope.client.SyncopeClientFactoryBean;
import org.apache.syncope.common.SyncopeClientException;
import org.apache.syncope.common.services.UserService;
import org.apache.syncope.common.to.MembershipTO;
import org.apache.syncope.common.to.UserTO;
import org.apache.syncope.common.types.CipherAlgorithm;
import org.apache.syncope.common.types.RESTHeaders;
import org.jasig.cas.authentication.DefaultHandlerResult;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import mx.japs.portal.configuracion.utils.Encryptor;

public class SyncopeHandler extends AbstractUsernamePasswordAuthenticationHandler {
	protected final Logger logger = LoggerFactory.getLogger(getClass());
	private String address;
	private String adminUser;
	private String adminPass;
	private String anonymousUser;
	private String anonymousPass;
	
	private SyncopeClientFactoryBean clientFactory;
    private SyncopeClient client;

	@Override
	protected HandlerResult authenticateUsernamePasswordInternal(UsernamePasswordCredential transformedCredential)
			throws GeneralSecurityException, PreventedException {
		
		String uiUsuario = transformedCredential.getUsername();
		String uiPassword = transformedCredential.getPassword();
		logger.debug("uiUsuario {}", uiUsuario);
		
		clientFactory = new SyncopeClientFactoryBean().setAddress(address);
		client = clientFactory.create(adminUser, adminPass);
		
		// TODO Auto-generated method stub
		Long idUsuario = null;
		try {
			idUsuario = Long.valueOf(client.getService(UserService.class).getUserId(uiUsuario).getHeaderString(RESTHeaders.USER_ID));
		} catch(SyncopeClientException e){
			logger.error("No se encontro el usuario", e);
		}
		
		if(idUsuario != null) {
			logger.info("Usuario encontrado con idUsuario {}", idUsuario);
			
			UserTO usuario = client.getService(UserService.class).read(idUsuario);

			String encodePassword = usuario.getPassword();
			logger.info("encodePassword {}", encodePassword);
			
			boolean esValido = new Encryptor().verify(uiPassword, CipherAlgorithm.SHA1, encodePassword);
			logger.info("esValido {}", esValido);

			if(esValido){
				List listaRoles = usuario.getMemberships();
				logger.info("listaRoles {}", listaRoles.size());
				
				List<GrantedAuthority> grantedAuths = new ArrayList<>();
				for(int i = 0; i < listaRoles.size(); i++){
					MembershipTO mm = (MembershipTO) listaRoles.get(i);
					logger.info("role {}", mm.getRoleName());
					
					grantedAuths.add(new SimpleGrantedAuthority(mm.getRoleName()));
				}
			} else {
				throw new FailedLoginException("Usuario / Contraseña no validos");
			}
		} else {
			throw new FailedLoginException("Usuario / Contraseña no validos");
		}
		DefaultHandlerResult x;
		
		return createHandlerResult(transformedCredential, this.principalFactory.createPrincipal(uiUsuario), null);
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public String getAdminUser() {
		return adminUser;
	}

	public void setAdminUser(String adminUser) {
		this.adminUser = adminUser;
	}

	public String getAdminPass() {
		return adminPass;
	}

	public void setAdminPass(String adminPass) {
		this.adminPass = adminPass;
	}

	public String getAnonymousUser() {
		return anonymousUser;
	}

	public void setAnonymousUser(String anonymousUser) {
		this.anonymousUser = anonymousUser;
	}

	public String getAnonymousPass() {
		return anonymousPass;
	}

	public void setAnonymousPass(String anonymousPass) {
		this.anonymousPass = anonymousPass;
	}
}
