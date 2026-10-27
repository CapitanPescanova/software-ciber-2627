package com.honeypot.honeypot.service;

import com.honeypot.honeypot.config.FuerzaBrutaConfig;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import java.time.Instant;
import org.springframework.stereotype.Service;

/**
 * Decide qué tipo de ataque es cada intento (HP-12).
 * Está en un servicio para que lo puedan usar el login web, el SSH y el FTP.
 */
@Service
public class ClasificadorAtaquesService {

    public static final String FUERZA_BRUTA = "fuerza_bruta";

    private final LoginAttemptRepository loginAttemptRepository;
    private final FuerzaBrutaConfig fuerzaBrutaConfig;

    public ClasificadorAtaquesService(LoginAttemptRepository loginAttemptRepository,
            FuerzaBrutaConfig fuerzaBrutaConfig) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.fuerzaBrutaConfig = fuerzaBrutaConfig;
    }

    /**
     * Devuelve la etiqueta del intento, o null si no encaja en ningún patrón.
     * Se llama ANTES de guardar el intento: si esa IP ya tiene el máximo de intentos
     * dentro de la ventana, el nuevo es el sexto (o más) y se etiqueta como fuerza bruta.
     */
    public String clasificar(String ip, Instant momento) {
        if (ip == null || momento == null) {
            return null;
        }
        Instant desde = momento.minusSeconds(fuerzaBrutaConfig.getVentanaSegundos());
        long anteriores = loginAttemptRepository.countBySourceIpAndOccurredAtAfter(ip, desde);
        return anteriores >= fuerzaBrutaConfig.getMaxIntentos() ? FUERZA_BRUTA : null;
    }
}