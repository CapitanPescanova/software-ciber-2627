package com.ciberurjc.siem.services;

import com.ciberurjc.siem.models.Event;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class EventService {

    private static final Logger logger = LoggerFactory.getLogger(EventService.class);

    public void processIncomingEvent(Event event) {
        logger.info("=========================================");
        logger.info("[MOCK INGESTA] Evento recibido correctamente");
        logger.info("ID: {} | Módulo: {} | Severidad: {}", event.event_id(), event.source(), event.severity());
        logger.info("Tipo: {}", event.event_type());
        logger.info("Título: {} | Descripción: {}", event.title(), event.description());
        logger.info("Timestamp: {}", event.timestamp());
        logger.info("=========================================");
    }
}