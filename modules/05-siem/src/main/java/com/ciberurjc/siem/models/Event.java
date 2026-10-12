package com.ciberurjc.siem.models;

import java.util.Map;

public record Event(
    String event_id,
    String timestamp,
    String source,
    String event_type,
    String severity,
    String title,
    String description,
    Map<String, Object> details
) {}