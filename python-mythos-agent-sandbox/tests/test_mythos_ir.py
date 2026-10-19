from mythos.agent_defense import MythosAiThreatDetector, PreProdIncidentResponseEngine

def test_mythos_blocks_prompt_injected_bmc_command_and_unsandboxed_agents():
    detector = MythosAiThreatDetector()
    strict_sandbox = {
        "seccomp_bpf_active": True,
        "unprivileged_userns": True,
        "readonly_rootfs": True
    }

    # 1. Prompt injection attempting to flash GPU firmware
    malicious = detector.evaluate_agent_tool_call(
        "agent- research-01",
        "nvflash --index=0 rogue_vbios.rom",
        strict_sandbox,
        egress_bytes_mb=1.2
    )
    assert malicious["verdict"] == "QUARANTINE_AGENT_PROMPT_INJECTION_DETECTED"
    assert malicious["mythos_risk_score"] >= 99.0

    # 2. Nominal sandboxed compile action
    benign = detector.evaluate_agent_tool_call(
        "agent-research-01",
        "pytest tests/test_tensor_parallel.py",
        strict_sandbox,
        egress_bytes_mb=2.5
    )
    assert benign["verdict"] == "ALLOW_SANDBOXED_TOOL_CALL"

def test_incident_response_playbook_isolates_infiniband_pkey_breach():
    ir = PreProdIncidentResponseEngine()
    report = ir.execute_ir_dr_playbook(
        "gb200-nvl72-rack04-node09",
        ["IB_ALERT: PKEY_MISMATCH on mlx5_0", "UNAUTHORIZED_RDMA write attempt"]
    )
    assert report["executive_risk_tier"] == "CRITICAL_SEV1"
    assert len(report["automated_dr_containment_steps"]) == 3
    assert report["rto_recovery_target_minutes"] <= 10
