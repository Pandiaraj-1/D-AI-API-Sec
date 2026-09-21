package com.aisecfirewall.gateway.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ScoreResponseDTO {

    @JsonProperty("isolation_score")
    public double isolationScore;

    @JsonProperty("xgboost_score")
    public double xgboostScore;

    @JsonProperty("final_score")
    public double finalScore;

    public String decision; // ALLOW | CHALLENGE | BLOCK

    public String reason;
}
