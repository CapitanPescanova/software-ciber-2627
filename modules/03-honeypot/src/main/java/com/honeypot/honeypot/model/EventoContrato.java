package com.honeypot.honeypot.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

public record EventoContrato(
    @JsonProperty("event_id") String eventId,
    String timestamp,
    String source,
    @JsonProperty("source_ip") String sourceIp,
    String service,
    String severity,
    @JsonProperty("event_type") String eventType,
    Map<String, Object> details
) {}
