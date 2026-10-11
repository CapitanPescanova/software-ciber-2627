import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public class SiemMockServer {

    private static final int PORT = 8081;

    // Campos obligatorios acordados con el Grupo 5 en el contrato de eventos
    private static final List<String> CAMPOS_OBLIGATORIOS = Arrays.asList(
            "\"event_id\"",
            "\"timestamp\"",
            "\"source\"",
            "\"event_type\"",
            "\"severity\"",
            "\"source_ip\"",
            "\"service\"",
            "\"details\""
    );

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/events", new EventsHandler());
        server.setExecutor(null); // Ejecutor por defecto

        System.out.println("=== SIEM Mock Server arrancado en http://localhost:" + PORT + "/events ===");
        server.start();
    }

    static class EventsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                enviarRespuesta(exchange, 405, "{\"error\": \"Metodo no permitido, use POST\"}");
                return;
            }

            // 1. Leer el cuerpo del JSON recibido
            InputStream is = exchange.getRequestBody();
            String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);

            System.out.println("\n[SIEM Mock] Evento recibido:");
            System.out.println(body);

            // 2. Validar que contenga todos los campos obligatorios del contrato
            boolean esValido = true;
            StringBuilder camposFaltantes = new StringBuilder();

            for (String campo : CAMPOS_OBLIGATORIOS) {
                if (!body.contains(campo)) {
                    esValido = false;
                    camposFaltantes.append(campo).append(" ");
                }
            }

            // 3. Responder 200 si es valido o 400 si falta algun campo
            if (esValido && !body.trim().isEmpty()) {
                System.out.println("-> Validacion OK: Retornando 200 OK");
                String respuesta = "{\"status\": \"received\"}";
                enviarRespuesta(exchange, 200, respuesta);
            } else {
                System.out.println("-> Error de validacion. Faltan: " + camposFaltantes + "-> Retornando 400 Bad Request");
                String respuesta = "{\"status\": \"error\", \"message\": \"Faltan campos obligatorios: " 
                        + camposFaltantes.toString().replace("\"", "") + "\"}";
                enviarRespuesta(exchange, 400, respuesta);
            }
        }

        private void enviarRespuesta(HttpExchange exchange, int statusCode, String responseText) throws IOException {
            byte[] bytes = responseText.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }
}