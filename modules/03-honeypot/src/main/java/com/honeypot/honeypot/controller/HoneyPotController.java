package com.honeypot.honeypot.controller;

import com.honeypot.honeypot.model.LoginAttempt;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HoneyPotController {
	private static final Logger log = LoggerFactory.getLogger(HoneyPotController.class);

	private final LoginAttemptRepository loginAttemptRepository;

	public HoneyPotController(LoginAttemptRepository loginAttemptRepository) {
		this.loginAttemptRepository = loginAttemptRepository;
	}

	@GetMapping({"/", "/login"})
	public String login() {
		return "login";
	}

	@PostMapping("/login")
	public String submitLogin(@RequestParam MultiValueMap<String, String> parameters,
			HttpServletRequest request, Model model) {
		String password = firstValue(parameters, "password", "pass", "pwd");
		LoginAttempt attempt = new LoginAttempt();
		attempt.setSourceIp(request.getRemoteAddr());
		attempt.setOccurredAt(Instant.now());
		attempt.setServiceAttacked("honeypot-web");
		attempt.setUsername(truncate(firstValue(parameters, "email", "username", "user"), 320));
		attempt.setCredentialAttempt(truncate(password, 2000));
		attempt.setPasswordLength(password == null ? null : password.length());
		attempt.setAttemptedCommand(truncate(firstValue(parameters, "command", "cmd"), 2000));
		attempt.setRequestPath(truncate(request.getRequestURI(), 512));
		attempt.setUserAgent(truncate(request.getHeader("User-Agent"), 512));
		loginAttemptRepository.save(attempt);

		// La contraseña no se escribe en el log a propósito.
		log.info("Intento guardado: ip={} servicio={} usuario={} total={}",
				attempt.getSourceIp(), attempt.getServiceAttacked(),
				limpiar(attempt.getUsername()), loginAttemptRepository.count());

		model.addAttribute("message", "Credenciales incorrectas.");
		return "login";
	}

	private static String firstValue(MultiValueMap<String, String> parameters, String... names) {
		for (String name : names) {
			List<String> values = parameters.get(name);
			if (values != null && !values.isEmpty()) {
				return values.get(0);
			}
		}
		return null;
	}

	private static String truncate(String value, int maxLength) {
		return value == null || value.length() <= maxLength ? value : value.substring(0, maxLength);
	}

	// El usuario lo escribe el atacante: quitamos los saltos de línea
	// para que no pueda inventarse líneas falsas en nuestros logs (log injection).
	private static String limpiar(String value) {
		return value == null ? null : value.replaceAll("[\\r\\n]", "_");
	}
}