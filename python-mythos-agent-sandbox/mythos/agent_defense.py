from typing import Dict, Any, List

class MythosAiThreatDetector:
    """
    Layers 12, 13 & 14: Securing AI Agents via Sandboxing and Mythos AI-Based Behavioral Threat Detection.
    Detects indirect prompt injection, autonomous lateral movement, BMC tampering, and weight exfiltration.
    """

    FORBIDDEN_CAPABILITIES = (
        "ipmitool",
        "bmc_reset",
        "nvflash",
        "opensm_pkey_override",
        "curl http://169.254.169.254",
        "/dev/mem",
        "insmod"
    )

    def evaluate_agent_tool_call(
        self,
        agent_id: str,
        tool_command: str,
        sandbox_profile: Dict[str, bool],
        egress_bytes_mb: float
    ) -> Dict[str, Any]:
        cmd_lower = tool_command.lower()

        # 1. Verify Mandatory AI Agent Sandboxing Controls (Seccomp + UserNS + ReadOnly RootFS)
        if not (
            sandbox_profile.get("seccomp_bpf_active", False)
            and sandbox_profile.get("unprivileged_userns", False)
            and sandbox_profile.get("readonly_rootfs", False)
        ):
            return {
                "agent_id": agent_id,
                "verdict": "BLOCK_UNSANDBOXED_AI_AGENT",
                "mythos_risk_score": 98.0,
                "reason": "AI Agent missing mandatory Seccomp-BPF, UserNS, or Read-Only RootFS sandbox controls."
            }

        # 2. Detect Prompt-Injected Privileged Tool / Firmware / BMC Commands
        for forbidden in self.FORBIDDEN_CAPABILITIES:
            if forbidden in cmd_lower:
                return {
                    "agent_id": agent_id,
                    "verdict": "QUARANTINE_AGENT_PROMPT_INJECTION_DETECTED",
                    "mythos_risk_score": 99.5,
                    "matched_signature": forbidden,
                    "reason": f"Mythos blocked unauthorized hardware/cluster command: {forbidden}"
                }

        # 3. Detect Model Weight / Checkpoint Exfiltration Anomaly
        if egress_bytes_mb > 500.0:
            return {
                "agent_id": agent_id,
                "verdict": "BLOCK_WEIGHT_EXFILTRATION_ANOMALY",
                "mythos_risk_score": 92.0,
                "reason": "Anomalous high-volume outbound transfer from sandboxed AI agent."
            }

        return {
            "agent_id": agent_id,
            "verdict": "ALLOW_SANDBOXED_TOOL_CALL",
            "mythos_risk_score": 4.5,
            "reason": "Nominal sandboxed AI agent execution."
        }


class PreProdIncidentResponseEngine:
    """
    Layers 15, 16 & 17: Pre-Production Cluster Incident Response (IR), Disaster Recovery (DR),
    and Automated Root-Cause Analysis (RCA) with Executive Risk Reporting.
    """

    def execute_ir_dr_playbook(self, node_id: str, telemetry_alerts: List[str]) -> Dict[str, Any]:
        combined = " ".join(telemetry_alerts).upper()
        containment_actions: List[str] = []
        root_cause = "Unclassified telemetry anomaly"
        executive_risk_tier = "MODERATE"

        if "PKEY_MISMATCH" in combined or "UNAUTHORIZED_RDMA" in combined:
            root_cause = "Cross-tenant InfiniBand RDMA queue-pair isolation breach attempt"
            executive_risk_tier = "CRITICAL_SEV1"
            containment_actions = [
                f"Revoke InfiniBand P_Key membership on {node_id} via OpenSM M_Key control plane",
                f"Drain Slurm compute partition on {node_id} and scrub HBM3e GPU VRAM",
                "Rotate FreeIPA host mTLS certificates and trigger DR golden image re-attestation"
            ]
        elif "FIRMWARE_DIGEST_MISMATCH" in combined or "SPDM_FAIL" in combined:
            root_cause = "Pre-production GPU tray SPDM firmware measurement drift or unauthorized flash"
            executive_risk_tier = "CRITICAL_SEV1"
            containment_actions = [
                f"Isolate {node_id} BMC VRF and trigger hardware Root-of-Trust golden firmware rollback",
                "Preserve eBPF ring-buffer forensic audit snapshot in tamper-evident Merkle vault"
            ]

        return {
            "affected_cluster_node": node_id,
            "executive_risk_tier": executive_risk_tier,
            "root_cause_analysis": root_cause,
            "automated_dr_containment_steps": containment_actions,
            "rto_recovery_target_minutes": 8
        }
