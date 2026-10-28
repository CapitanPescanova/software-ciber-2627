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

    /** event_type que se envía al SIEM cuando el intento no tiene etiqueta (acuerdo con el grupo 5). */
    public static final String INTENTO_LOGIN = "intento_login";

    private final LoginAttemptRepository loginAttemptRepository;
    private final FuerzaBrutaConfig fuerzaBrutaConfig;

    public ClasificadorAtaquesService(LoginAttemptRepository loginAttemptRepository,
            FuerzaBrutaConfig fuerzaBrutaConfig) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.fuerzaBrutaConfig = fuerzaBrutaConfig;
    }

    /**
     * Devuelve la etiqueta del intento, o null si no encaja en ningún patrón
     * (en la BD se queda sin etiqueta y al SIEM se envía INTENTO_LOGIN, ver EventoMapper).
     * Se llama ANTES de guardar el intento: si esa IP ya tiene el máximo de intentos
     * dentro de la ventana, el nuevo es el sexto (o más) y se etiqueta como fuerza bruta.
     * Solo cuentan los intentos con contraseña: el FTP guarda una fila por cada comando
     * (USER, LIST...) y esas filas no son intentos de login (HP-78).
     */
    public String clasificar(String ip, Instant momento) {
        if (ip == null || momento == null) {
            return null;
        }
        Instant desde = momento.minusSeconds(fuerzaBrutaConfig.getVentanaSegundos());
        long anteriores = loginAttemptRepository
                .countBySourceIpAndOccurredAtAfterAndCredentialAttemptIsNotNull(ip, desde);
        return anteriores >= fuerzaBrutaConfig.getMaxIntentos() ? FUERZA_BRUTA : null;
    }
}