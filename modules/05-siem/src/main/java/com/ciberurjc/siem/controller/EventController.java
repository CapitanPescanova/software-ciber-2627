package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.services.EventService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/events")
public class EventController {

    private final EventService eventService;

    public EventController(EventService eventService) {
        this.eventService = eventService;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> receiveEvent(@RequestBody Event event) {
        
        // Validación ESTRICTA basada en el Contrato SCRUM-6 / SEM-6
        if (event.event_id() == null || event.event_id().trim().isEmpty() ||
            event.timestamp() == null || event.timestamp().trim().isEmpty() ||
            event.source() == null || event.source().trim().isEmpty() ||
            event.event_type() == null || event.event_type().trim().isEmpty() ||
            event.severity() == null || event.severity().trim().isEmpty() ||
            event.title() == null || event.title().trim().isEmpty() ||
            event.description() == null || event.description().trim().isEmpty() ||
            event.details() == null) {

            return ResponseEntity.badRequest().body(Map.of(
                "error", Map.of(
                    "code", "VALIDATION_ERROR",
                    "message", "Faltan campos obligatorios o están vacíos según el contrato."
                )
            ));
        }

        eventService.processIncomingEvent(event);

        // El contrato exige un 201 Created y este JSON exacto
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
            "status", "accepted",
            "source", event.source(),
            "event_id", event.event_id()
        ));
    }
}