package com.honeypot.honeypot.config;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Lista de credenciales por defecto (HP-82).
 * Se lee de application.properties con el formato usuario:contraseña separados por comas,
 * así se pueden añadir credenciales sin tocar el código. Si falta la propiedad, la lista está vacía.
 */
@Component
public class CredencialesPorDefectoConfig {

    private final Set<String> credenciales;

    public CredencialesPorDefectoConfig(@Value("${honeypot.credenciales-por-defecto:}") String lista) {
        this.credenciales = Arrays.stream(lista.split(","))
                .map(String::trim)
                .filter(credencial -> !credencial.isEmpty())
                .collect(Collectors.toSet());
    }

    /** true si la pareja usuario/contraseña está en la lista. */
    public boolean esPorDefecto(String usuario, String contrasena) {
        if (usuario == null || contrasena == null) {
            return false;
        }
        return credenciales.contains(usuario.trim() + ":" + contrasena);
    }

    public Set<String> getCredenciales() {
        return credenciales;
    }
}
