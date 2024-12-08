package com.generation.blogpessoal.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.generation.blogpessoal.model.Usuario;

public class UserDetailsImpl implements UserDetails{
	
	private static final long serialVersionUID = 1L;
	
	private String userName;
	private String password;
	private List<GrantedAuthority> authorities;
	
	public UserDetailsImpl(Usuario user) {
		this.userName = user.getUsuario();
		this.password = user.getSenha();
	}
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities(){
		
		return authorities;
	}
	
	@Override
	public String getPassword() {
		
		return password;
	}
	
	@Override
	public String getUsername() {
		return userName;
	}
	
	@Override
	public boolean isAccountNonExpired() {
		/*indica se o acesso do usuário expirou(tempo de acesso). Uma conta expirada nao pode autenticada
		* caso expire: return false */
		return true;
	}
	
	@Override
	public boolean isAccountNonLocked() {
		/* indica se o usuário está bloqueado ou desbloqueado. Um usuário bloqueado não pode ser autenticado
		 * caso bloqueado: return false */
		return true;
	}
	
	@Override
	public boolean isCredentialsNonExpired() {
		/* Inica se as credenciais do usuario (senha) expiraram (precisa troca). Senha expirada nao pode ser autenticada
		 * caso bloqueada: return false*/
		return true;
	}
	
	@Override
	public boolean isEnabled() {
		/* indica se o usuario esta habilitado ou desabilitado. Usuario desabilitado nao pode ser autenticado
		 * caso desabilitado: return false*/
		return true;
	}

}
