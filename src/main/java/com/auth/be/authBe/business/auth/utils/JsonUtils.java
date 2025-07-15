package com.auth.be.authBe.business.auth.utils;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class JsonUtils {
    public String minifyJson(String jsonStr) {
        String result = null;
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readValue(jsonStr, JsonNode.class);
            result = jsonNode.toString();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return result;
    }
}
