//! Blackwell-Aegis-OS Layers 6 to 11 (Memory-Safe Rust Security):
//! - Layer 6 & 7: InfiniBand Partition Key (P_Key) & Subnet Manager Management Key (M_Key) Validator
//! - Layer 8 & 9: Enroot / Docker / Kubernetes Container Workload Security Policy Enforcer
//! - Layer 10 & 11: Zero-Trust VRF (Virtual Routing & Forwarding) and VLAN Micro-Segmentation Firewall

#[derive(Debug, Clone, PartialEq)]
pub enum InfiniBandVerdict {
    AllowRdmaQueuePair,
    DenyDefaultPartitionForbidden,
    DenyInvalidManagementKey,
    DenyTenantPKeyMismatch,
}

#[derive(Debug, Clone)]
pub struct IbFabricPacket {
    pub tenant_assigned_pkey: u16,
    pub packet_pkey: u16,
    pub subnet_mkey_provided: u64,
    pub expected_subnet_mkey: u64,
    pub is_subnet_management_smp: bool,
}

/// Layers 6 & 7: High-Speed InfiniBand Fabric P_Key / M_Key Security Controller
pub fn inspect_infiniband_fabric_frame(frame: &IbFabricPacket) -> InfiniBandVerdict {
    // Disallow default unisolated partition key (0x7FFF / 0xFFFF) on multi-tenant AI clusters
    if frame.packet_pkey == 0x7FFF || frame.packet_pkey == 0xFFFF {
        return InfiniBandVerdict::DenyDefaultPartitionForbidden;
    }

    // Protect Subnet Manager SMP mad packets with 64-bit M_Key verification
    if frame.is_subnet_management_smp && frame.subnet_mkey_provided != frame.expected_subnet_mkey {
        return InfiniBandVerdict::DenyInvalidManagementKey;
    }

    // Strip high membership bit (0x8000) to compare 15-bit base P_Key
    let base_assigned = frame.tenant_assigned_pkey & 0x7FFF;
    let base_packet = frame.packet_pkey & 0x7FFF;
    if base_assigned != base_packet {
        return InfiniBandVerdict::DenyTenantPKeyMismatch;
    }

    InfiniBandVerdict::AllowRdmaQueuePair
}

/// Layers 8 & 9: Enroot / Docker / Kubernetes Container Spec Hardener
#[derive(Debug, Clone)]
pub struct ContainerRuntimeSpec {
    pub runtime_engine: String, // "enroot", "docker", "containerd"
    pub rootless_userns: bool,
    pub no_new_privileges: bool,
    pub host_network_shared: bool,
    pub visible_gpu_uuids: Vec<String>,
}

pub fn validate_container_isolation(spec: &ContainerRuntimeSpec) -> Result<&'static str, &'static str> {
    if !spec.rootless_userns {
        return Err("CONTAINER_VIOLATION_ROOT_USERNS_FORBIDDEN");
    }
    if !spec.no_new_privileges {
        return Err("CONTAINER_VIOLATION_MISSING_NO_NEW_PRIVS");
    }
    if spec.host_network_shared {
        return Err("CONTAINER_VIOLATION_HOST_NETNS_EXPOSED");
    }
    if spec.visible_gpu_uuids.is_empty() || spec.visible_gpu_uuids.iter().any(|g| g == "ALL") {
        return Err("CONTAINER_VIOLATION_UNSCOPED_GPU_DEVICES");
    }
    Ok("ENROOT_CONTAINER_HARDENED_OK")
}

/// Layers 10 & 11: Zero-Trust VRF & VLAN East-West Cluster Firewall
pub fn authorize_vrf_vlan_flow(src_vrf: &str, dst_vrf: &str, vlan_id: u16, dst_port: u16) -> bool {
    if vlan_id == 1 || vlan_id > 4094 {
        return false; // Native VLAN 1 forbidden by Zero-Trust policy
    }
    if src_vrf == dst_vrf {
        return true;
    }
    // Cross-VRF traffic is strictly blocked unless destined for the OIDC/Kerberos Identity Gateway (443)
    dst_vrf == "VRF_IDENTITY_CONTROL_PLANE" && dst_port == 443
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infiniband_pkey_and_mkey_isolation() {
        let valid_rdma = IbFabricPacket {
            tenant_assigned_pkey: 0x8104,
            packet_pkey: 0x8104,
            subnet_mkey_provided: 0x9988776655443322,
            expected_subnet_mkey: 0x9988776655443322,
            is_subnet_management_smp: true,
        };
        assert_eq!(inspect_infiniband_fabric_frame(&valid_rdma), InfiniBandVerdict::AllowRdmaQueuePair);

        let default_pkey_attack = IbFabricPacket {
            tenant_assigned_pkey: 0x8104,
            packet_pkey: 0xFFFF,
            subnet_mkey_provided: 0,
            expected_subnet_mkey: 0x9988776655443322,
            is_subnet_management_smp: false,
        };
        assert_eq!(
            inspect_infiniband_fabric_frame(&default_pkey_attack),
            InfiniBandVerdict::DenyDefaultPartitionForbidden
        );
    }

    #[test]
    fn test_enroot_container_rejects_unscoped_gpu_or_root_namespace() {
        let hardened_enroot = ContainerRuntimeSpec {
            runtime_engine: String::from("enroot"),
            rootless_userns: true,
            no_new_privileges: true,
            host_network_shared: false,
            visible_gpu_uuids: vec![String::from("GPU-a1b2c3d4-0001")],
        };
        assert_eq!(validate_container_isolation(&hardened_enroot), Ok("ENROOT_CONTAINER_HARDENED_OK"));

        let insecure_docker = ContainerRuntimeSpec {
            runtime_engine: String::from("docker"),
            rootless_userns: true,
            no_new_privileges: true,
            host_network_shared: false,
            visible_gpu_uuids: vec![String::from("ALL")],
        };
        assert_eq!(
            validate_container_isolation(&insecure_docker),
            Err("CONTAINER_VIOLATION_UNSCOPED_GPU_DEVICES")
        );
    }

    #[test]
    fn test_zero_trust_vrf_vlan_firewall_blocks_vlan1_and_lateral_movement() {
        assert!(!authorize_vrf_vlan_flow("VRF_TENANT_A", "VRF_TENANT_A", 1, 8080));
        assert!(authorize_vrf_vlan_flow("VRF_TENANT_A", "VRF_TENANT_A", 240, 29500));
        assert!(!authorize_vrf_vlan_flow("VRF_TENANT_A", "VRF_TENANT_B", 240, 22));
        assert!(authorize_vrf_vlan_flow("VRF_TENANT_A", "VRF_IDENTITY_CONTROL_PLANE", 240, 443));
    }
}
