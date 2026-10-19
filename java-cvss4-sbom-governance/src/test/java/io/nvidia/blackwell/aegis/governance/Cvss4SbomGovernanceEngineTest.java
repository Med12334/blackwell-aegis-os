package io.nvidia.blackwell.aegis.governance;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class Cvss4SbomGovernanceEngineTest {

    private final Cvss4SbomGovernanceEngine engine = new Cvss4SbomGovernanceEngine();

    @Test
    void shouldFlagCriticalCvss4VulnerabilityAndEnforce24HourBlockSla() throws Exception {
        var criticalComponent = new Cvss4SbomGovernanceEngine.SbomComponent(
            "pkg:deb/ubuntu/linux-image-nvidia-gb200@6.8.0",
            "sha256:99aabbccddeeff",
            true,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        );

        var report = engine.evaluateComponentRisk(criticalComponent);
        assertEquals(10.0, report.cvss4Score());
        assertEquals("CRITICAL", report.severityRating());
        assertFalse(report.supplyChainCompliant());
        assertEquals("IMMEDIATE_24H_PREPROD_BLOCK_AND_PATCH", report.executiveRemediationSla());
        assertEquals(64, report.merkleAuditSealSha256().length());
    }

    @Test
    void shouldApproveSignedLowRiskSbomComponent() throws Exception {
        var safeComponent = new Cvss4SbomGovernanceEngine.SbomComponent(
            "pkg:cargo/blackwell-rust-fabric-guard@1.0.0",
            "sha256:11223344556677",
            true,
            "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
        );

        var report = engine.evaluateComponentRisk(safeComponent);
        assertEquals(5.0, report.cvss4Score());
        assertEquals("MEDIUM", report.severityRating());
        assertTrue(report.supplyChainCompliant());
    }
}
