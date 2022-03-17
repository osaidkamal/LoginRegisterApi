package com.api.login.response;

public class MessageInfoResponse {
    private String message;

    public MessageInfoResponse(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}