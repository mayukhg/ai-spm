"""
AI-Specific Threat Detection Configuration
Configurable threat detection modules for the AI Scanner Service
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

class ThreatSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class DetectionMethod(Enum):
    GRADIENT_ANALYSIS = "gradient_analysis"
    INFERENCE_PATTERN = "inference_pattern_analysis"
    MEMBERSHIP_INFERENCE = "membership_inference_detection"
    INPUT_PERTURBATION = "input_perturbation_analysis"
    CONFIDENCE_MONITORING = "prediction_confidence_monitoring"
    QUERY_PATTERN = "query_pattern_analysis"
    OUTPUT_SIMILARITY = "output_similarity_detection"
    API_USAGE_PATTERN = "api_usage_pattern_analysis"
    BEHAVIOR_REPLICATION = "model_behavior_replication_detection"

@dataclass
class ThreatDetectionRule:
    name: str
    enabled: bool
    severity: ThreatSeverity
    detection_methods: List[DetectionMethod]
    thresholds: Dict[str, float]
    response_actions: List[str]

class AIThreatDetectionConfig:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "/server/config/threat-detection-config.json"
        self.config_data = self._load_config()
        self.logger = logging.getLogger(__name__)
        
    def _load_config(self) -> Dict[str, Any]:
        """Load threat detection configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.warning(f"Config file not found: {self.config_path}. Using defaults.")
            return self._get_default_config()
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in config file: {e}. Using defaults.")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration if file loading fails"""
        return {
            "aiSpecificThreats": {
                "modelInversionAttacks": {
                    "enabled": True,
                    "severity": "high",
                    "detectionMethods": ["gradient_analysis"],
                    "thresholds": {"suspiciousInferenceCount": 1000},
                    "responseActions": ["log_incident"]
                }
            },
            "detectionSettings": {
                "scanInterval": 300,
                "retentionPeriod": 2592000,
                "alertCooldown": 900,
                "batchSize": 1000
            }
        }
    
    def get_enabled_threats(self) -> List[ThreatDetectionRule]:
        """Get list of enabled threat detection rules"""
        enabled_threats = []
        threats_config = self.config_data.get("aiSpecificThreats", {})
        
        for threat_name, threat_config in threats_config.items():
            if threat_config.get("enabled", False):
                rule = ThreatDetectionRule(
                    name=threat_name,
                    enabled=threat_config["enabled"],
                    severity=ThreatSeverity(threat_config.get("severity", "medium")),
                    detection_methods=[
                        DetectionMethod(method) for method in threat_config.get("detectionMethods", [])
                    ],
                    thresholds=threat_config.get("thresholds", {}),
                    response_actions=threat_config.get("responseActions", [])
                )
                enabled_threats.append(rule)
        
        return enabled_threats
    
    def get_detection_settings(self) -> Dict[str, Any]:
        """Get general detection settings"""
        return self.config_data.get("detectionSettings", {})
    
    def get_risk_scoring_config(self) -> Dict[str, Any]:
        """Get risk scoring configuration"""
        return self.config_data.get("riskScoring", {})
    
    def get_integration_settings(self) -> Dict[str, Any]:
        """Get integration settings for SIEM, alerts, etc."""
        return self.config_data.get("integrations", {})
    
    def is_threat_enabled(self, threat_name: str) -> bool:
        """Check if a specific threat detection is enabled"""
        threats = self.config_data.get("aiSpecificThreats", {})
        return threats.get(threat_name, {}).get("enabled", False)
    
    def get_threat_thresholds(self, threat_name: str) -> Dict[str, float]:
        """Get thresholds for a specific threat"""
        threats = self.config_data.get("aiSpecificThreats", {})
        return threats.get(threat_name, {}).get("thresholds", {})
    
    def get_response_actions(self, threat_name: str) -> List[str]:
        """Get response actions for a specific threat"""
        threats = self.config_data.get("aiSpecificThreats", {})
        return threats.get(threat_name, {}).get("responseActions", [])
    
    def reload_config(self) -> bool:
        """Reload configuration from file"""
        try:
            self.config_data = self._load_config()
            self.logger.info("Configuration reloaded successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to reload configuration: {e}")
            return False
    
    def update_threat_status(self, threat_name: str, enabled: bool) -> bool:
        """Enable or disable a specific threat detection"""
        try:
            if "aiSpecificThreats" not in self.config_data:
                self.config_data["aiSpecificThreats"] = {}
            
            if threat_name not in self.config_data["aiSpecificThreats"]:
                self.logger.warning(f"Threat {threat_name} not found in configuration")
                return False
            
            self.config_data["aiSpecificThreats"][threat_name]["enabled"] = enabled
            
            # Save back to file
            with open(self.config_path, 'w') as f:
                json.dump(self.config_data, f, indent=2)
            
            self.logger.info(f"Threat {threat_name} {'enabled' if enabled else 'disabled'}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update threat status: {e}")
            return False
    
    def add_custom_threat(self, threat_config: Dict[str, Any]) -> bool:
        """Add a new custom threat detection rule"""
        try:
            threat_name = threat_config.get("name")
            if not threat_name:
                self.logger.error("Threat name is required")
                return False
            
            if "aiSpecificThreats" not in self.config_data:
                self.config_data["aiSpecificThreats"] = {}
            
            self.config_data["aiSpecificThreats"][threat_name] = {
                "enabled": threat_config.get("enabled", True),
                "severity": threat_config.get("severity", "medium"),
                "detectionMethods": threat_config.get("detectionMethods", []),
                "thresholds": threat_config.get("thresholds", {}),
                "responseActions": threat_config.get("responseActions", ["log_incident"])
            }
            
            # Save back to file
            with open(self.config_path, 'w') as f:
                json.dump(self.config_data, f, indent=2)
            
            self.logger.info(f"Custom threat {threat_name} added successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add custom threat: {e}")
            return False

# Global configuration instance
threat_config = AIThreatDetectionConfig()

# Convenience functions for easy access
def get_enabled_threats() -> List[ThreatDetectionRule]:
    return threat_config.get_enabled_threats()

def is_threat_enabled(threat_name: str) -> bool:
    return threat_config.is_threat_enabled(threat_name)

def get_threat_thresholds(threat_name: str) -> Dict[str, float]:
    return threat_config.get_threat_thresholds(threat_name)

def reload_threat_config() -> bool:
    return threat_config.reload_config()