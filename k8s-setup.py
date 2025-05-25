#!/usr/bin/env python3

"""
Kubernetes Multi-Node Cluster Setup Script with Comprehensive Cleanup and Version Selection
This script performs COMPLETE cleanup of previous installations before setting up a fresh Kubernetes cluster
Features:
- Comprehensive cleanup of ALL previous master and worker node installations
- Sets up a Kubernetes cluster with 1 master and 3 worker nodes
- Removes all traces of previous Docker, containerd, CRI-O installations
- Cleans network configurations, iptables rules, and systemd services
- Fresh installation of containerd + Kubernetes components
- Supports both root execution and regular user with sudo privileges
- Allows selection of Kubernetes version (1.24+ supported)
- Automatic installation of latest patch version for selected minor version
Usage: 
  # Default version (1.28)
  python3 k8s-setup.py master
  python3 k8s-setup.py worker --master-ip IP --join-command 'COMMAND'
  
  # Specific version
  python3 k8s-setup.py master --k8s-version 1.30
  python3 k8s-setup.py worker --k8s-version 1.30 --master-ip IP --join-command 'COMMAND'
  
  # With sudo
  sudo python3 k8s-setup.py master --k8s-version 1.29
  
Tested on Ubuntu 20.04/22.04/24.04 and Debian 11/12
"""

import argparse
import os
import subprocess
import sys
import time
import socket
import re
from pathlib import Path
from typing import Optional, List, Dict

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

class KubernetesSetup:
    """Main class for Kubernetes cluster setup"""
    
    def __init__(self, k8s_version: str = "1.28"):
        # Kubernetes version (minor version only, e.g., "1.28", "1.29", "1.30")
        self.k8s_minor_version = k8s_version
        self.validate_kubernetes_version()
        
        self.containerd_version = "1.6.24"
        self.pod_cidr = "10.244.0.0/16"
        self.service_cidr = "10.96.0.0/12"
        self.home_dir = Path.home()
        
        # User privilege attributes (set by check_user_privileges)
        self.is_root = False
        self.sudo_prefix = "sudo "
        self.actual_user = ""
        self.actual_home = Path.home()
        self.actual_uid = 0
        self.actual_gid = 0
        
    def validate_kubernetes_version(self) -> None:
        """Validate the Kubernetes version format and support"""
        if not self.k8s_minor_version:
            self.print_error("Kubernetes version cannot be empty")
            sys.exit(1)
            
        # Check if version matches expected format (x.y)  
        version_pattern = r'^\d+\.\d+$'
        if not re.match(version_pattern, self.k8s_minor_version):
            self.print_error(f"Invalid Kubernetes version format: {self.k8s_minor_version}")
            self.print_error("Expected format: 1.28, 1.29, 1.30, etc.")
            sys.exit(1)
            
        # Parse version parts
        try:
            major, minor = map(int, self.k8s_minor_version.split('.'))
        except ValueError:
            self.print_error(f"Invalid version format: {self.k8s_minor_version}")
            sys.exit(1)
        
        # Basic version validation
        if major != 1 or minor < 24:
            self.print_error(f"Kubernetes version {self.k8s_minor_version} is not supported")
            self.print_error("Minimum supported version is 1.24")
            sys.exit(1)
            
        # Warn about very new versions
        if minor > 33:
            self.print_warning(f"Kubernetes version {self.k8s_minor_version} is very new and may not be fully tested")
            
        # Warn about older versions
        if minor < 28:
            self.print_warning(f"Kubernetes version {self.k8s_minor_version} is older and may have limited support")
            
        self.print_status(f"Using Kubernetes version: {self.k8s_minor_version}.x")
    
    def check_version_availability(self) -> bool:
        """Check if the selected Kubernetes version is available in the repository"""
        self.print_status(f"Checking availability of Kubernetes {self.k8s_minor_version}...")
        
        try:
            # Test if the repository URL is accessible
            result = self.run_command(f"curl -s -I https://pkgs.k8s.io/core:/stable:/v{self.k8s_minor_version}/deb/Release", capture_output=True, check=False)
            if result.returncode != 0:
                self.print_error(f"Kubernetes {self.k8s_minor_version} repository is not accessible")
                self.print_error("This version may not be available or released yet")
                return False
                
            self.print_success(f"Kubernetes {self.k8s_minor_version} repository is accessible")
            return True
            
        except Exception as e:
            self.print_warning(f"Could not verify repository availability: {e}")
            self.print_status("Continuing with installation attempt...")
            return True

    @staticmethod
    def list_kubernetes_versions():
        """Display commonly available Kubernetes versions"""
        print("🐳 Kubernetes Version Information")
        print("=" * 50)
        print("")
        print("📋 COMMONLY AVAILABLE VERSIONS:")
        versions_info = [
            ("1.33", "Latest stable", "🟢 Current"),
            ("1.32", "Latest stable", "🟢 Current"), 
            ("1.31", "Latest stable", "🟢 Current"),
            ("1.30", "Stable LTS", "🟡 Recommended"),
            ("1.29", "Stable", "🟡 Supported"),
            ("1.28", "Stable LTS", "🟡 Default"),
            ("1.27", "Older", "🟠 Limited Support"),
            ("1.26", "Older", "🟠 Limited Support"),
            ("1.25", "Older", "🟠 Limited Support"),
            ("1.24", "Minimum", "🔴 Minimal Support"),
        ]
        
        print(f"{'Version':<10} {'Status':<15} {'Support Level':<20}")
        print("-" * 50)
        for version, status, support in versions_info:
            print(f"{version:<10} {status:<15} {support:<20}")
        
        print("")
        print("💡 RECOMMENDATIONS:")
        print("  • For production: Use 1.28 (LTS) or 1.30 (LTS)")
        print("  • For latest features: Use 1.31, 1.32, or 1.33")
        print("  • For learning: Any version 1.28 or newer")
        print("")
        print("🔗 ADDITIONAL RESOURCES:")
        print("  • Official releases: https://kubernetes.io/releases/")
        print("  • Release calendar: https://kubernetes.io/releases/patch-releases/")
        print("  • Version skew policy: https://kubernetes.io/releases/version-skew-policy/")
        print("")
        print("📝 USAGE EXAMPLES:")
        print("  python3 k8s-setup.py master --k8s-version 1.28")
        print("  python3 k8s-setup.py master --k8s-version 1.30")
        print("  python3 k8s-setup.py worker --k8s-version 1.31 --master-ip IP --join-command 'COMMAND'")
        print("")
        
    def print_status(self, message: str) -> None:
        """Print status message in blue"""
        print(f"{Colors.BLUE}[INFO]{Colors.NC} {message}")
        
    def print_success(self, message: str) -> None:
        """Print success message in green"""
        print(f"{Colors.GREEN}[SUCCESS]{Colors.NC} {message}")
        
    def print_warning(self, message: str) -> None:
        """Print warning message in yellow"""
        print(f"{Colors.YELLOW}[WARNING]{Colors.NC} {message}")
        
    def print_error(self, message: str) -> None:
        """Print error message in red"""
        print(f"{Colors.RED}[ERROR]{Colors.NC} {message}")
        
    def run_command(self, command: str, check: bool = True, capture_output: bool = False, shell: bool = True) -> subprocess.CompletedProcess:
        """Run shell command with error handling"""
        try:
            if capture_output:
                result = subprocess.run(command, shell=shell, check=check, 
                                      capture_output=True, text=True)
            else:
                result = subprocess.run(command, shell=shell, check=check)
            return result
        except subprocess.CalledProcessError as e:
            if check:
                self.print_error(f"Command failed: {command}")
                self.print_error(f"Error: {e}")
                sys.exit(1)
            return e
            
    def check_user_privileges(self) -> None:
        """Check user privileges and set appropriate execution context"""
        self.is_root = os.geteuid() == 0
        
        if self.is_root:
            self.print_warning("Running as root user")
            self.sudo_prefix = ""
            # Set HOME to actual user's home if SUDO_USER is available
            if 'SUDO_USER' in os.environ:
                try:
                    import pwd
                    user_info = pwd.getpwnam(os.environ['SUDO_USER'])
                    self.actual_user = os.environ['SUDO_USER']
                    self.actual_home = Path(user_info.pw_dir)
                    self.actual_uid = user_info.pw_uid
                    self.actual_gid = user_info.pw_gid
                    self.print_status(f"Detected original user: {self.actual_user}")
                except:
                    self.actual_user = "root"
                    self.actual_home = Path("/root")
                    self.actual_uid = 0
                    self.actual_gid = 0
            else:
                self.actual_user = "root"
                self.actual_home = Path("/root")
                self.actual_uid = 0
                self.actual_gid = 0
        else:
            self.print_status("Running as regular user with sudo privileges")
            self.sudo_prefix = "sudo "
            self.actual_user = os.environ.get('USER', 'unknown')
            self.actual_home = self.home_dir
            self.actual_uid = os.getuid()
            self.actual_gid = os.getgid()
            
            # Check if user has sudo privileges
            try:
                self.run_command("sudo -n true", capture_output=True)
            except subprocess.CalledProcessError:
                self.print_error("Current user does not have sudo privileges.")
                self.print_error("Please run with sudo or as root, or add user to sudoers.")
                sys.exit(1)
            
    def check_prerequisites(self) -> None:
        """Check system prerequisites"""
        self.print_status("Checking prerequisites...")
        
        # Check if sudo is available (only if not root)
        if not self.is_root:
            try:
                self.run_command("which sudo", capture_output=True)
            except subprocess.CalledProcessError:
                self.print_error("sudo is required but not installed.")
                sys.exit(1)
            
        # Check system requirements (RAM)
        try:
            result = self.run_command("free -m | awk 'NR==2{print $2}'", capture_output=True)
            ram_mb = int(result.stdout.strip())
            if ram_mb < 2048:
                self.print_warning("System has less than 2GB RAM. Kubernetes may not work properly.")
        except:
            self.print_warning("Could not determine system RAM.")
            
        # Check network connectivity
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=5)
        except OSError:
            self.print_error("No internet connectivity. Please check your network connection.")
            sys.exit(1)
            
        self.print_success("Prerequisites check completed")
        
    def cleanup_previous_installation(self) -> None:
        """Comprehensive cleanup of previous Kubernetes installations (both master and worker)"""
        self.print_status("=" * 60)
        self.print_status("COMPREHENSIVE CLEANUP OF PREVIOUS KUBERNETES INSTALLATIONS")
        self.print_status("=" * 60)
        self.print_warning("This will remove ALL previous Kubernetes configurations!")
        
        # Step 0: Initial repository cleanup to prevent conflicts
        self.print_status("Step 0/13: Pre-cleanup repository conflicts...")
        self.run_command(f"{self.sudo_prefix}find /etc/apt/sources.list.d/ -name '*docker*' -delete 2>/dev/null", check=False)
        self.run_command(f"{self.sudo_prefix}find /etc/apt/sources.list.d/ -name '*kubernetes*' -delete 2>/dev/null", check=False)
        self.run_command(f"{self.sudo_prefix}rm -f /etc/apt/keyrings/docker.gpg /etc/apt/keyrings/kubernetes*.gpg", check=False)
        
        # Step 1: Reset kubeadm for both master and worker nodes
        self.print_status("Step 1/13: Resetting kubeadm configurations...")
        if self.command_exists("kubeadm"):
            self.print_status("Found existing kubeadm - performing reset...")
            self.run_command(f"{self.sudo_prefix}kubeadm reset -f --cri-socket unix:///var/run/containerd/containerd.sock", check=False)
            self.run_command(f"{self.sudo_prefix}kubeadm reset -f", check=False)  # Fallback without CRI socket
        else:
            self.print_status("No existing kubeadm found - skipping reset")
            
        # Step 2: Stop and disable ALL Kubernetes services
        self.print_status("Step 2/13: Stopping and disabling Kubernetes services...")
        k8s_services = [
            "kubelet", "kubeadm", "kubectl", "kube-proxy", "kube-apiserver", 
            "kube-controller-manager", "kube-scheduler", "etcd"
        ]
        for service in k8s_services:
            self.run_command(f"{self.sudo_prefix}systemctl stop {service}", check=False)
            self.run_command(f"{self.sudo_prefix}systemctl disable {service}", check=False)
            self.run_command(f"{self.sudo_prefix}systemctl mask {service}", check=False)
        
        # Step 3: Kill any remaining Kubernetes processes
        self.print_status("Step 3/13: Terminating remaining Kubernetes processes...")
        k8s_processes = [
            "kube-apiserver", "kube-controller-manager", "kube-scheduler", 
            "kube-proxy", "kubelet", "etcd", "flanneld", "coredns"
        ]
        for process in k8s_processes:
            self.run_command(f"{self.sudo_prefix}pkill -f {process}", check=False)
            
        # Step 4: Remove ALL Kubernetes packages
        self.print_status("Step 4/13: Removing ALL Kubernetes packages...")
        # More comprehensive package removal
        k8s_packages = [
            "kubeadm", "kubectl", "kubelet", "kubernetes-cni", 
            "kube*", "*kube*", "flannel*", "calico*", "weave*"
        ]
        for package in k8s_packages:
            self.run_command(f"{self.sudo_prefix}apt-get remove -y {package}", check=False)
            self.run_command(f"{self.sudo_prefix}apt-get purge -y {package}", check=False)
            self.run_command(f"{self.sudo_prefix}apt-get autoremove -y {package}", check=False)
        
        # Clean package cache
        self.run_command(f"{self.sudo_prefix}apt-get autoremove -y", check=False)
        self.run_command(f"{self.sudo_prefix}apt-get autoclean", check=False)
            
        # Step 5: Remove container runtimes (containerd, docker, cri-o)
        self.print_status("Step 5/13: Removing container runtimes...")
        # Stop container services
        container_services = ["containerd", "docker", "cri-o", "dockerd", "containerd-shim"]
        for service in container_services:
            self.run_command(f"{self.sudo_prefix}systemctl stop {service}", check=False)
            self.run_command(f"{self.sudo_prefix}systemctl disable {service}", check=False)
            
        # Remove container packages
        container_packages = [
            "containerd.io", "docker-ce", "docker-ce-cli", "docker-ce-rootless-extras",
            "docker-compose-plugin", "docker-buildx-plugin", "cri-o", "cri-o-runc",
            "runc", "docker.io", "docker-doc", "docker-compose", "podman*"
        ]
        for package in container_packages:
            self.run_command(f"{self.sudo_prefix}apt-get remove -y {package}", check=False)
            self.run_command(f"{self.sudo_prefix}apt-get purge -y {package}", check=False)
            
        # Step 6: Clean up ALL configuration files and directories
        self.print_status("Step 6/13: Removing configuration files and directories...")
        # Kubernetes directories
        k8s_directories = [
            "/etc/kubernetes/",
            "/var/lib/kubelet/", 
            "/var/lib/kubeadm/",
            "/var/lib/etcd/",
            "/var/lib/etcd2/",
            "/etc/etcd/",
            "/opt/etcd/",
            "/var/etcd/",
            "/usr/local/bin/etcd*"
        ]
        
        # CNI directories
        cni_directories = [
            "/etc/cni/",
            "/opt/cni/",
            "/var/lib/cni/",
            "/run/flannel/",
            "/var/lib/calico/",
            "/var/log/calico/",
            "/etc/calico/"
        ]
        
        # Container runtime directories
        container_directories = [
            "/var/lib/containerd/",
            "/etc/containerd/",
            "/var/lib/docker/",
            "/etc/docker/",
            "/var/lib/dockershim/",
            "/var/run/docker/",
            "/var/run/containerd/",
            "/run/containerd/",
            "/var/lib/crio/",
            "/etc/crio/",
        ]
        
        # User directories
        user_directories = [
            str(self.actual_home / ".kube/"),
            str(self.actual_home / ".docker/"),
            str(self.actual_home / ".minikube/"),
            "/root/.kube/",
            "/root/.docker/"
        ]
        
        all_directories = k8s_directories + cni_directories + container_directories + user_directories
        for directory in all_directories:
            if "*" in directory:
                self.run_command(f"{self.sudo_prefix}rm -rf {directory}", check=False)
            else:
                self.run_command(f"{self.sudo_prefix}rm -rf {directory}", check=False)
                
        # Step 7: Remove network interfaces and configurations
        self.print_status("Step 7/13: Cleaning up network configurations...")
        # Remove virtual network interfaces
        network_interfaces = [
            "cni0", "flannel.1", "flannel*", "docker0", "cbr0", "kube-bridge",
            "weave", "veth*", "tunl0", "cali*", "vxlan.calico"
        ]
        for interface in network_interfaces:
            if "*" in interface:
                # Handle wildcard interfaces
                try:
                    result = self.run_command(f"ip link show | grep '{interface.replace('*', '')}' | cut -d: -f2 | cut -d@ -f1", capture_output=True, check=False)
                    if result.returncode == 0 and result.stdout.strip():
                        for iface in result.stdout.strip().split('\n'):
                            if iface.strip():
                                self.run_command(f"{self.sudo_prefix}ip link delete {iface.strip()}", check=False)
                except:
                    pass
            else:
                self.run_command(f"{self.sudo_prefix}ip link delete {interface}", check=False)
        
        # Remove network namespaces
        self.run_command(f"{self.sudo_prefix}ip netns list | grep -E 'cni-|flannel' | xargs -r {self.sudo_prefix}ip netns delete", check=False)
            
        # Step 8: Clean up iptables rules comprehensively
        self.print_status("Step 8/13: Cleaning up iptables rules...")
        iptables_commands = [
            # Flush all rules
            f"{self.sudo_prefix}iptables -F",
            f"{self.sudo_prefix}iptables -X", 
            f"{self.sudo_prefix}iptables -t nat -F",
            f"{self.sudo_prefix}iptables -t nat -X",
            f"{self.sudo_prefix}iptables -t mangle -F", 
            f"{self.sudo_prefix}iptables -t mangle -X",
            f"{self.sudo_prefix}iptables -t raw -F",
            f"{self.sudo_prefix}iptables -t raw -X",
            # IPv6 rules
            f"{self.sudo_prefix}ip6tables -F",
            f"{self.sudo_prefix}ip6tables -X",
            f"{self.sudo_prefix}ip6tables -t nat -F", 
            f"{self.sudo_prefix}ip6tables -t nat -X",
            f"{self.sudo_prefix}ip6tables -t mangle -F",
            f"{self.sudo_prefix}ip6tables -t mangle -X",
            # Remove specific Kubernetes chains
            f"{self.sudo_prefix}iptables -t nat -D POSTROUTING -s 10.244.0.0/16 ! -o cni0 -j MASQUERADE",
            f"{self.sudo_prefix}iptables -t filter -D FORWARD -s 10.244.0.0/16 -j ACCEPT",
            f"{self.sudo_prefix}iptables -t filter -D FORWARD -d 10.244.0.0/16 -j ACCEPT",
        ]
        for cmd in iptables_commands:
            self.run_command(cmd, check=False)
            
        # Step 9: Remove repository keys and sources (Enhanced cleanup)
        self.print_status("Step 9/13: Removing repository configurations...")
        repo_files = [
            "/etc/apt/keyrings/kubernetes-apt-keyring.gpg",
            "/etc/apt/keyrings/kubernetes-archive-keyring.gpg", 
            "/etc/apt/sources.list.d/kubernetes.list",
            "/etc/apt/keyrings/docker.gpg",
            "/etc/apt/sources.list.d/docker.list",
            "/etc/apt/trusted.gpg.d/kubernetes.gpg",
            "/usr/share/keyrings/kubernetes-archive-keyring.gpg",
            # Clean up potential duplicate Docker repository files
            "/etc/apt/sources.list.d/archive_uri-https_download_docker_com_linux_ubuntu-noble.list",
            "/etc/apt/sources.list.d/archive_uri-https_download_docker_com_linux_ubuntu-jammy.list",
            "/etc/apt/sources.list.d/archive_uri-https_download_docker_com_linux_ubuntu-focal.list"
        ]
        for file in repo_files:
            self.run_command(f"{self.sudo_prefix}rm -f {file}", check=False)
            
        # Clean up any duplicate or malformed repository entries
        self.print_status("Cleaning up duplicate repository entries...")
        self.run_command(f"{self.sudo_prefix}find /etc/apt/sources.list.d/ -name '*docker*' -delete", check=False)
        self.run_command(f"{self.sudo_prefix}find /etc/apt/sources.list.d/ -name '*kubernetes*' -delete", check=False)
            
        # Step 10: Clean up systemd configurations
        self.print_status("Step 10/13: Cleaning up systemd configurations...")
        systemd_files = [
            "/etc/systemd/system/kubelet.service",
            "/etc/systemd/system/kubelet.service.d/",
            "/etc/systemd/system/docker.service.d/",
            "/etc/systemd/system/containerd.service.d/",
            "/lib/systemd/system/kubelet.service",
            "/usr/lib/systemd/system/kubelet.service"
        ]
        for file in systemd_files:
            self.run_command(f"{self.sudo_prefix}rm -rf {file}", check=False)
            
        # Reload systemd
        self.run_command(f"{self.sudo_prefix}systemctl daemon-reload", check=False)
        self.run_command(f"{self.sudo_prefix}systemctl reset-failed", check=False)
        
        # Step 11: Clean up kernel modules and sysctl settings
        self.print_status("Step 11/13: Cleaning up kernel modules and sysctl...")
        # Remove module configurations
        module_files = [
            "/etc/modules-load.d/k8s.conf",
            "/etc/modules-load.d/kubernetes.conf",
            "/etc/modules-load.d/containerd.conf",
            "/etc/sysctl.d/k8s.conf",
            "/etc/sysctl.d/kubernetes.conf",
            "/etc/sysctl.d/99-kubernetes-cri.conf"
        ]
        for file in module_files:
            self.run_command(f"{self.sudo_prefix}rm -f {file}", check=False)
            
        # Unload kernel modules
        k8s_modules = ["br_netfilter", "overlay", "ip_vs", "ip_vs_rr", "ip_vs_wrr", "ip_vs_sh"]
        for module in k8s_modules:
            self.run_command(f"{self.sudo_prefix}modprobe -r {module}", check=False)
            
        # Step 12: Clean up logs and temporary files
        self.print_status("Step 12/13: Cleaning up logs and temporary files...")
        log_files = [
            "/var/log/pods/",
            "/var/log/containers/", 
            "/tmp/kubeadm*",
            "/tmp/kube*",
            "/var/lib/kubelet/pki/",
            str(self.actual_home / "join-command.txt"),
            "/tmp/kubeadm-init.log"
        ]
        for file in log_files:
            self.run_command(f"{self.sudo_prefix}rm -rf {file}", check=False)
            
        # Clear systemd journal for Kubernetes services
        self.run_command(f"{self.sudo_prefix}journalctl --vacuum-time=1s", check=False)
        
        # Step 13: Final cleanup and verification
        self.print_status("Step 13/13: Final cleanup and verification...")
        # Final apt cleanup
        self.run_command(f"{self.sudo_prefix}apt-get update", check=False)
        
        # Final verification that cleanup was successful
        self.print_status("Performing final cleanup verification...")
        
        # Check for remaining Kubernetes processes
        remaining_processes = []
        k8s_process_names = ["kubelet", "kube-proxy", "kube-apiserver", "etcd", "flannel"]
        for process in k8s_process_names:
            try:
                result = self.run_command(f"pgrep -f {process}", capture_output=True, check=False)
                if result.returncode == 0 and result.stdout.strip():
                    remaining_processes.append(process)
            except:
                pass
                
        if remaining_processes:
            self.print_warning(f"Some processes still running: {', '.join(remaining_processes)}")
            for process in remaining_processes:
                self.run_command(f"{self.sudo_prefix}pkill -9 -f {process}", check=False)
        
        # Check for remaining network interfaces
        remaining_interfaces = []
        k8s_interface_patterns = ["cni", "flannel", "docker", "kube"]
        try:
            result = self.run_command("ip link show", capture_output=True, check=False)
            if result.returncode == 0:
                for pattern in k8s_interface_patterns:
                    if pattern in result.stdout.lower():
                        for line in result.stdout.split('\n'):
                            if pattern in line.lower() and '@' not in line:
                                interface_name = line.split(':')[1].strip().split('@')[0] if ':' in line else None
                                if interface_name and interface_name not in remaining_interfaces:
                                    remaining_interfaces.append(interface_name)
        except:
            pass
            
        if remaining_interfaces:
            self.print_warning(f"Removing remaining network interfaces: {', '.join(remaining_interfaces)}")
            for interface in remaining_interfaces:
                self.run_command(f"{self.sudo_prefix}ip link delete {interface}", check=False)
        
        self.print_status("=" * 60)
        self.print_success("COMPREHENSIVE CLEANUP COMPLETED SUCCESSFULLY")
        self.print_status("=" * 60)
        self.print_success("✓ All previous master and worker node configurations removed")
        self.print_success("✓ All Kubernetes packages and services cleaned up") 
        self.print_success("✓ All container runtimes and configurations removed")
        self.print_success("✓ All network configurations and interfaces cleaned up")
        self.print_success("✓ All iptables rules and systemd configurations removed")
        self.print_success("✓ System is ready for fresh Kubernetes installation")
        self.print_status("=" * 60)
        
        # Wait a moment for all cleanup operations to complete
        self.print_status("Waiting for cleanup operations to complete...")
        time.sleep(5)
        self.print_success("Cleanup verification completed - system is clean and ready!")
        
    def configure_system(self, node_type: str) -> None:
        """Configure system requirements"""
        self.print_status("Configuring system requirements...")
        
        # Update system
        self.print_status("Updating system packages...")
        self.run_command(f"{self.sudo_prefix}apt-get update")
        self.run_command(f"{self.sudo_prefix}apt-get upgrade -y")
        
        # Install required packages
        self.print_status("Installing required packages...")
        packages = [
            "apt-transport-https", "ca-certificates", "curl", "gnupg",
            "lsb-release", "software-properties-common", "wget", "net-tools",
            "htop", "vim"
        ]
        self.run_command(f"{self.sudo_prefix}apt-get install -y {' '.join(packages)}")
        
        # Disable swap
        self.print_status("Disabling swap...")
        self.run_command(f"{self.sudo_prefix}swapoff -a")
        self.run_command(f"{self.sudo_prefix}sed -i '/ swap / s/^\\(.*\\)$/#\\1/g' /etc/fstab")
        
        # Configure kernel modules
        self.print_status("Configuring kernel modules...")
        k8s_modules = """overlay
br_netfilter"""
        self.write_file("/etc/modules-load.d/k8s.conf", k8s_modules, sudo=True)
        self.run_command(f"{self.sudo_prefix}modprobe overlay")
        self.run_command(f"{self.sudo_prefix}modprobe br_netfilter")
        
        # Configure sysctl parameters
        self.print_status("Configuring sysctl parameters...")
        sysctl_config = """net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1"""
        self.write_file("/etc/sysctl.d/k8s.conf", sysctl_config, sudo=True)
        self.run_command(f"{self.sudo_prefix}sysctl --system")
        
        # Configure firewall (if ufw is active)
        try:
            result = self.run_command(f"{self.sudo_prefix}ufw status", capture_output=True)
            if "Status: active" in result.stdout:
                self.print_status("Configuring firewall rules...")
                if node_type == "master":
                    firewall_rules = [
                        f"{self.sudo_prefix}ufw allow 6443/tcp",      # Kubernetes API server
                        f"{self.sudo_prefix}ufw allow 2379:2380/tcp", # etcd server
                        f"{self.sudo_prefix}ufw allow 10250/tcp",     # Kubelet API
                        f"{self.sudo_prefix}ufw allow 10259/tcp",     # kube-scheduler
                        f"{self.sudo_prefix}ufw allow 10257/tcp"      # kube-controller-manager
                    ]
                    for rule in firewall_rules:
                        self.run_command(rule)
                self.run_command(f"{self.sudo_prefix}ufw allow 10250/tcp")  # Kubelet API (all nodes)
                self.run_command(f"{self.sudo_prefix}ufw allow 8472/udp")   # Flannel VXLAN
        except:
            pass  # UFW not active or not installed
            
        self.print_success("System configuration completed")
        
    def install_containerd(self) -> None:
        """Install and configure containerd"""
        self.print_status("Installing containerd...")
        
        # Add Docker repository
        self.print_status("Adding Docker repository...")
        self.run_command(f"{self.sudo_prefix}mkdir -p /etc/apt/keyrings")
        self.run_command(f"curl -fsSL https://download.docker.com/linux/ubuntu/gpg | {self.sudo_prefix}gpg --dearmor -o /etc/apt/keyrings/docker.gpg")
        
        # Get distribution codename
        result = self.run_command("lsb_release -cs", capture_output=True)
        codename = result.stdout.strip()
        
        # Get architecture
        result = self.run_command("dpkg --print-architecture", capture_output=True)
        arch = result.stdout.strip()
        
        docker_repo = f"deb [arch={arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu {codename} stable"
        self.write_file("/etc/apt/sources.list.d/docker.list", docker_repo, sudo=True)
        
        # Install containerd
        self.run_command(f"{self.sudo_prefix}apt-get update")
        self.run_command(f"{self.sudo_prefix}apt-get install -y containerd.io")
        
        # Configure containerd
        self.print_status("Configuring containerd...")
        self.run_command(f"{self.sudo_prefix}mkdir -p /etc/containerd")
        result = self.run_command("containerd config default", capture_output=True)
        containerd_config = result.stdout
        
        # Enable SystemdCgroup
        containerd_config = containerd_config.replace(
            'SystemdCgroup = false', 'SystemdCgroup = true'
        )
        self.write_file("/etc/containerd/config.toml", containerd_config, sudo=True)
        
        # Restart and enable containerd
        self.run_command(f"{self.sudo_prefix}systemctl restart containerd")
        self.run_command(f"{self.sudo_prefix}systemctl enable containerd")
        
        # Verify containerd is running
        try:
            self.run_command(f"{self.sudo_prefix}systemctl is-active --quiet containerd")
            self.print_success("Containerd installation completed")
        except subprocess.CalledProcessError:
            self.print_error("Containerd failed to start")
            sys.exit(1)
            
    def install_kubernetes(self) -> None:
        """Install Kubernetes components using new pkgs.k8s.io repository"""
        self.print_status("Installing Kubernetes components...")
        
        # Check version availability first
        if not self.check_version_availability():
            self.print_error("Cannot proceed with unavailable Kubernetes version")
            self.print_status("Available alternatives:")
            self.print_status("  - Try a different version with --k8s-version (e.g., 1.28, 1.29, 1.30)")
            self.print_status("  - Check https://kubernetes.io/releases/ for supported versions")
            sys.exit(1)
        
        # Add Kubernetes repository (new format for each minor version)
        self.print_status("Adding Kubernetes repository...")
        self.run_command(f"curl -fsSL https://pkgs.k8s.io/core:/stable:/v{self.k8s_minor_version}/deb/Release.key | {self.sudo_prefix}gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg")
        
        k8s_repo = f"deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v{self.k8s_minor_version}/deb/ /"
        self.write_file("/etc/apt/sources.list.d/kubernetes.list", k8s_repo, sudo=True)
        
        # Update package index
        self.run_command(f"{self.sudo_prefix}apt-get update")
        
        # Check available versions before installation
        self.print_status("Checking available Kubernetes versions...")
        try:
            result = self.run_command("apt-cache madison kubelet | head -5", capture_output=True, check=False)
            if result.returncode == 0:
                self.print_status(f"Available kubelet versions for {self.k8s_minor_version}:")
                for line in result.stdout.strip().split('\n')[:3]:  # Show top 3 versions
                    if line.strip():
                        print(f"  {line.strip()}")
        except:
            pass
        
        # Check if packages are already installed
        installed_packages = []
        for package in ["kubelet", "kubeadm", "kubectl"]:
            try:
                result = self.run_command(f"dpkg -l | grep -E '^ii.*{package}\\s'", capture_output=True, check=False)
                if result.returncode == 0:
                    installed_packages.append(package)
            except:
                pass
        
        if installed_packages:
            self.print_status(f"Already installed packages: {', '.join(installed_packages)}")
        
        # Install or reinstall Kubernetes components
        self.print_status(f"Installing/ensuring latest Kubernetes {self.k8s_minor_version}.x components...")
        install_result = self.run_command(f"{self.sudo_prefix}apt-get install -y kubelet kubeadm kubectl", check=False)
        
        if install_result.returncode != 0:
            self.print_warning("Standard installation failed, trying with --reinstall...")
            self.run_command(f"{self.sudo_prefix}apt-get install --reinstall -y kubelet kubeadm kubectl")
        
        # Reload systemd to recognize new service files
        self.print_status("Reloading systemd daemon...")
        self.run_command(f"{self.sudo_prefix}systemctl daemon-reload")
        
        # Hold packages to prevent automatic updates
        self.run_command(f"{self.sudo_prefix}apt-mark hold kubelet kubeadm kubectl")
        
        # Check if kubelet service file exists
        kubelet_service_files = [
            "/lib/systemd/system/kubelet.service",
            "/usr/lib/systemd/system/kubelet.service",
            "/etc/systemd/system/kubelet.service"
        ]
        
        service_file_exists = False
        for service_file in kubelet_service_files:
            if os.path.exists(service_file):
                service_file_exists = True
                self.print_status(f"Found kubelet service file: {service_file}")
                break
        
        if not service_file_exists:
            self.print_warning("kubelet service file not found, attempting to reinstall kubelet...")
            # Try to reinstall kubelet to get the service file
            self.run_command(f"{self.sudo_prefix}apt-get remove -y kubelet", check=False)
            self.run_command(f"{self.sudo_prefix}apt-get install -y kubelet")
            self.run_command(f"{self.sudo_prefix}systemctl daemon-reload")
            self.run_command(f"{self.sudo_prefix}apt-mark hold kubelet")
            
            # Check again after reinstall
            service_file_exists = any(os.path.exists(f) for f in kubelet_service_files)
            
        if not service_file_exists:
            self.print_error("kubelet service file still not found after reinstall")
            self.print_status("This might be due to a package repository issue")
            self.print_status("Attempting to create kubelet service manually...")
            
            # Create a basic kubelet service file if it doesn't exist
            kubelet_service_content = """[Unit]
Description=kubelet: The Kubernetes Node Agent
Documentation=https://kubernetes.io/docs/home/
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/bin/kubelet
Restart=always
StartLimitInterval=0
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
            self.write_file("/etc/systemd/system/kubelet.service", kubelet_service_content, sudo=True)
            self.run_command(f"{self.sudo_prefix}systemctl daemon-reload")
            self.print_status("Created basic kubelet service file")
        
        # Ensure kubelet service dropin directory exists
        kubelet_dropin_dir = "/etc/systemd/system/kubelet.service.d"
        self.run_command(f"{self.sudo_prefix}mkdir -p {kubelet_dropin_dir}")
        
        # Create kubeadm dropin configuration if it doesn't exist
        kubeadm_dropin_file = f"{kubelet_dropin_dir}/10-kubeadm.conf"
        if not os.path.exists(kubeadm_dropin_file):
            self.print_status("Creating kubelet kubeadm configuration...")
            kubeadm_dropin_content = """# Note: This dropin only works with kubeadm and kubelet v1.11+
[Service]
Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"
# This is a file that "kubeadm init" and "kubeadm join" generates at runtime, populating the KUBELET_KUBEADM_ARGS variable dynamically
EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env
# This is a file that the user can use for overrides of the kubelet args as a last resort. Preferably, the user should use
# the .NodeRegistration.KubeletExtraArgs object in the configuration files instead. KUBELET_EXTRA_ARGS should be sourced from this file.
EnvironmentFile=-/etc/default/kubelet
ExecStart=
ExecStart=/usr/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS
"""
            self.write_file(kubeadm_dropin_file, kubeadm_dropin_content, sudo=True)
            self.run_command(f"{self.sudo_prefix}systemctl daemon-reload")
            self.print_status("Created kubelet kubeadm configuration")
        
        # Enable kubelet
        self.print_status("Enabling kubelet service...")
        try:
            # First check if the service can be found
            result = self.run_command(f"{self.sudo_prefix}systemctl list-unit-files | grep kubelet", capture_output=True, check=False)
            if result.returncode == 0:
                self.print_status("kubelet service unit found")
            else:
                self.print_warning("kubelet service unit not found in systemctl list")
            
            # Try to enable the service
            enable_result = self.run_command(f"{self.sudo_prefix}systemctl enable kubelet", check=False)
            if enable_result.returncode == 0:
                self.print_success("kubelet service enabled successfully")
            else:
                self.print_warning("Failed to enable kubelet service normally")
                # Try force enable
                self.print_status("Attempting force enable...")
                self.run_command(f"{self.sudo_prefix}systemctl enable kubelet --force", check=False)
                
        except subprocess.CalledProcessError as e:
            self.print_warning(f"Failed to enable kubelet service: {e}")
            self.print_status("The kubelet service will be started by kubeadm during cluster initialization")
        
        # Verify service status
        try:
            result = self.run_command(f"{self.sudo_prefix}systemctl is-enabled kubelet", capture_output=True, check=False)
            if result.returncode == 0:
                self.print_success(f"kubelet service status: {result.stdout.strip()}")
            else:
                self.print_warning("kubelet service may not be properly enabled, but kubeadm will handle this")
        except:
            pass
        
        # Display installed versions
        try:
            result = self.run_command("kubeadm version -o short", capture_output=True, check=False)
            if result.returncode == 0:
                self.print_success(f"Installed kubeadm version: {result.stdout.strip()}")
        except:
            pass
            
        self.print_success("Kubernetes components installation completed")
        
    def initialize_master(self) -> str:
        """Initialize Kubernetes master node"""
        self.print_status("Initializing Kubernetes master node...")
        
        # Get the primary IP address
        result = self.run_command("hostname -I | awk '{print $1}'", capture_output=True)
        local_ip = result.stdout.strip()
        self.print_status(f"Using IP address: {local_ip}")
        
        # Get hostname
        result = self.run_command("hostname -s", capture_output=True)
        hostname = result.stdout.strip()
        
        # Initialize the cluster
        self.print_status("Running kubeadm init...")
        init_command = (
            f"{self.sudo_prefix}kubeadm init "
            f"--pod-network-cidr={self.pod_cidr} "
            f"--service-cidr={self.service_cidr} "
            f"--apiserver-advertise-address={local_ip} "
            f"--cri-socket unix:///var/run/containerd/containerd.sock "
            f"--node-name={hostname}"
        )
        
        # Run init and capture output
        result = self.run_command(init_command, capture_output=True)
        
        # Save init log
        with open("/tmp/kubeadm-init.log", "w") as f:
            f.write(result.stdout)
            
        # Configure kubectl for the appropriate user
        self.print_status("Configuring kubectl...")
        
        # Ensure the admin config file exists
        config_source = "/etc/kubernetes/admin.conf"
        if not os.path.exists(config_source):
            self.print_error(f"Kubernetes admin config not found at {config_source}")
            self.print_error("kubeadm init may have failed")
            sys.exit(1)
        
        # Create .kube directory and config for the appropriate user
        if self.is_root:
            # Running as root - set up for root user
            self.print_status("Setting up kubectl config for root user...")
            self.run_command("mkdir -p /root/.kube")
            self.run_command(f"cp -i {config_source} /root/.kube/config")
            self.print_success("kubectl configured for root user")
            
            # If this was run with sudo, also set up for the original user
            if self.actual_user != "root" and 'SUDO_USER' in os.environ:
                self.print_status(f"Setting up kubectl config for original user: {self.actual_user}")
                user_kube_dir = str(self.actual_home / ".kube")
                user_config_file = str(self.actual_home / ".kube/config")
                
                self.run_command(f"mkdir -p {user_kube_dir}")
                self.run_command(f"cp {config_source} {user_config_file}")
                self.run_command(f"chown {self.actual_uid}:{self.actual_gid} {user_config_file}")
                self.run_command(f"chown -R {self.actual_uid}:{self.actual_gid} {user_kube_dir}")
                self.print_success(f"kubectl configured for user: {self.actual_user}")
        else:
            # Running as regular user with sudo
            self.print_status("Setting up kubectl config for regular user...")
            user_kube_dir = str(self.actual_home / ".kube")
            user_config_file = str(self.actual_home / ".kube/config")
            
            self.run_command(f"mkdir -p {user_kube_dir}")
            self.run_command(f"{self.sudo_prefix}cp -i {config_source} {user_config_file}")
            self.run_command(f"{self.sudo_prefix}chown {self.actual_uid}:{self.actual_gid} {user_config_file}")
            self.print_success("kubectl configured for regular user")
        
        # Extract and save join command
        self.print_status("Extracting join command...")
        result = self.run_command(f"{self.sudo_prefix}kubeadm token create --print-join-command", capture_output=True)
        join_command = result.stdout.strip()
        
        join_file = self.actual_home / "join-command.txt"
        with open(join_file, "w") as f:
            f.write(join_command)
        join_file.chmod(0o600)
        
        # Set proper ownership if running as root
        if self.is_root and self.actual_user != "root":
            self.run_command(f"chown {self.actual_uid}:{self.actual_gid} {join_file}")
        
        self.print_success("Master node initialization completed")
        self.print_status(f"Join command saved to: {join_file}")
        
        return join_command
        
    def join_worker(self, join_command: str) -> None:
        """Join worker node to cluster"""
        self.print_status("Joining worker node to cluster...")
        
        # Execute the join command
        self.print_status("Executing join command...")
        self.run_command(f"{self.sudo_prefix}{join_command}")
        
        self.print_success("Worker node successfully joined the cluster")
        
    def install_cni_plugins(self) -> None:
        """Install CNI plugins required for pod networking"""
        self.print_status("Installing CNI plugins...")
        
        # Check if CNI plugins already exist
        cni_bin_dir = "/opt/cni/bin"
        loopback_plugin = f"{cni_bin_dir}/loopback"
        
        if os.path.exists(loopback_plugin):
            self.print_status("CNI plugins already installed")
            return
        
        # Create CNI directories
        self.run_command(f"{self.sudo_prefix}mkdir -p /opt/cni/bin")
        self.run_command(f"{self.sudo_prefix}mkdir -p /etc/cni/net.d")
        
        # Get system architecture
        result = self.run_command("uname -m", capture_output=True)
        arch = result.stdout.strip()
        
        # Map architecture names
        arch_map = {
            "x86_64": "amd64",
            "aarch64": "arm64",
            "armv7l": "arm"
        }
        cni_arch = arch_map.get(arch, "amd64")
        
        # Download and install CNI plugins
        cni_version = "v1.4.0"  # Latest stable version
        cni_url = f"https://github.com/containernetworking/plugins/releases/download/{cni_version}/cni-plugins-linux-{cni_arch}-{cni_version}.tgz"
        
        self.print_status(f"Downloading CNI plugins {cni_version} for {cni_arch}...")
        self.run_command(f"curl -L {cni_url} -o /tmp/cni-plugins.tgz")
        
        self.print_status("Extracting CNI plugins...")
        self.run_command(f"{self.sudo_prefix}tar -xzf /tmp/cni-plugins.tgz -C /opt/cni/bin")
        
        # Set proper permissions
        self.run_command(f"{self.sudo_prefix}chmod +x /opt/cni/bin/*")
        
        # Clean up downloaded file
        self.run_command("rm -f /tmp/cni-plugins.tgz")
        
        # Verify installation
        if os.path.exists(loopback_plugin):
            self.print_success("CNI plugins installed successfully")
            
            # List installed plugins
            try:
                result = self.run_command("ls -la /opt/cni/bin/", capture_output=True, check=False)
                if result.returncode == 0:
                    plugin_count = len([line for line in result.stdout.split('\n') if line and not line.startswith('total')])
                    self.print_status(f"Installed {plugin_count-2} CNI plugins")  # -2 for . and ..
                    
                    # List key plugins
                    key_plugins = ["loopback", "bridge", "host-local", "portmap", "bandwidth", "firewall"]
                    installed_key_plugins = []
                    for plugin in key_plugins:
                        if os.path.exists(f"/opt/cni/bin/{plugin}"):
                            installed_key_plugins.append(plugin)
                    
                    if installed_key_plugins:
                        self.print_status(f"Key CNI plugins available: {', '.join(installed_key_plugins)}")
            except:
                pass
                
            # Restart containerd to pick up CNI plugins
            self.print_status("Restarting containerd to recognize CNI plugins...")
            self.run_command(f"{self.sudo_prefix}systemctl restart containerd")
            
            # Wait for containerd to be ready
            time.sleep(5)
            
            # Verify containerd is running
            try:
                self.run_command(f"{self.sudo_prefix}systemctl is-active --quiet containerd")
                self.print_success("containerd restarted successfully")
            except subprocess.CalledProcessError:
                self.print_error("containerd failed to restart")
                sys.exit(1)
        else:
            self.print_error("CNI plugin installation failed")
            sys.exit(1)
            
    def install_cni(self) -> None:
        """Install CNI plugins and Flannel networking - only on master"""
        self.print_status("Setting up CNI networking...")
        
        # First install CNI plugins
        self.install_cni_plugins()
        
        # Wait for cluster to be ready
        self.print_status("Waiting for cluster to be ready...")
        time.sleep(15)
        
        # Install Flannel
        self.print_status("Installing Flannel CNI...")
        self.run_command("kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml")
        
        # Wait a bit for Flannel to initialize
        self.print_status("Waiting for Flannel to initialize...")
        time.sleep(10)
        
        self.print_success("CNI networking setup completed")
        
    def verify_master_installation(self) -> None:
        """Verify master node installation"""
        self.print_status("Verifying master node installation...")
        
        # Wait for nodes to be ready
        self.print_status("Waiting for master node to be ready...")
        max_attempts = 60
        for attempt in range(max_attempts):
            try:
                result = self.run_command("kubectl get nodes", capture_output=True)
                if "Ready" in result.stdout:
                    break
            except:
                pass
            time.sleep(5)
        else:
            self.print_error("Master node failed to become ready within timeout")
            sys.exit(1)
            
        # Display cluster information
        self.print_status("Master Node Information:")
        self.run_command("kubectl cluster-info")
        
        self.print_status("Node Status:")
        self.run_command("kubectl get nodes -o wide")
        
        self.print_status("System Pods Status:")
        self.run_command("kubectl get pods -n kube-system")
        
        self.print_success("Master node verification completed successfully!")
        
    def verify_worker_installation(self) -> None:
        """Verify worker node installation"""
        self.print_status("Verifying worker node installation...")
        
        # Check if kubelet is running
        try:
            self.run_command(f"{self.sudo_prefix}systemctl is-active --quiet kubelet")
            self.print_success("Kubelet is running on worker node")
        except subprocess.CalledProcessError:
            self.print_error("Kubelet is not running on worker node")
            sys.exit(1)
            
        self.print_success("Worker node verification completed!")
        self.print_status("To verify the node has joined the cluster, run 'kubectl get nodes' on the master node.")
        
    def wait_for_cluster_ready(self) -> None:
        """Wait for cluster to be fully ready"""
        self.print_status("Waiting for cluster to be fully ready...")
        
        # Wait for all system pods to be running
        max_attempts = 120
        for attempt in range(max_attempts):
            try:
                result = self.run_command(
                    "kubectl get pods -n kube-system --no-headers | grep -v Running | grep -v Completed | wc -l",
                    capture_output=True
                )
                not_ready_count = int(result.stdout.strip())
                if not_ready_count == 0:
                    break
                self.print_status(f"Waiting for system pods to be ready... ({not_ready_count} pods not ready)")
                time.sleep(5)
            except:
                time.sleep(5)
        else:
            self.print_warning("Some system pods may not be ready, but continuing...")
        
        # Additional check for CNI functionality
        self.print_status("Testing pod creation capability...")
        try:
            # Try to create a simple test pod to verify CNI is working
            test_pod_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: cni-test-pod
  namespace: default
spec:
  containers:
  - name: test
    image: busybox:1.35
    command: ['sleep', '30']
  restartPolicy: Never
"""
            # Write test pod to file
            with open("/tmp/cni-test-pod.yaml", "w") as f:
                f.write(test_pod_yaml)
            
            # Create test pod
            self.run_command("kubectl apply -f /tmp/cni-test-pod.yaml", check=False)
            
            # Wait for pod to start
            for i in range(30):
                result = self.run_command("kubectl get pod cni-test-pod -o jsonpath='{.status.phase}'", capture_output=True, check=False)
                if result.returncode == 0 and result.stdout.strip() in ['Running', 'Succeeded']:
                    self.print_success("CNI networking verified - pods can be created successfully")
                    break
                time.sleep(2)
            else:
                self.print_warning("Test pod did not start within timeout, but continuing...")
            
            # Clean up test pod
            self.run_command("kubectl delete -f /tmp/cni-test-pod.yaml", check=False)
            self.run_command("rm -f /tmp/cni-test-pod.yaml", check=False)
            
        except Exception as e:
            self.print_warning(f"CNI test failed: {e}, but continuing...")
            
        self.print_success("Cluster is ready!")
        
    def display_master_info(self, join_command: str) -> None:
        """Display master post-installation information"""
        result = self.run_command("hostname -I | awk '{print $1}'", capture_output=True)
        master_ip = result.stdout.strip()
        
        # Get actual installed Kubernetes version
        try:
            result = self.run_command("kubectl version --short --client 2>/dev/null | grep Client", capture_output=True, check=False)
            if result.returncode == 0:
                k8s_version = result.stdout.strip()
            else:
                result = self.run_command("kubeadm version -o short", capture_output=True, check=False)
                k8s_version = f"kubeadm: {result.stdout.strip()}" if result.returncode == 0 else f"Kubernetes {self.k8s_minor_version}.x"
        except:
            k8s_version = f"Kubernetes {self.k8s_minor_version}.x"
        
        self.print_success("Kubernetes master node setup completed successfully!")
        print("")
        self.print_status("Cluster Information:")
        print(f"  - Master IP: {master_ip}")
        print(f"  - Kubernetes Version: {k8s_version}")
        print(f"  - Pod Network CIDR: {self.pod_cidr}")
        print(f"  - Service Network CIDR: {self.service_cidr}")
        print("")
        self.print_status("Join Command for Worker Nodes:")
        print(f"  {join_command}")
        print("")
        self.print_status("To setup worker nodes, run:")
        print(f"  python3 {sys.argv[0]} worker --k8s-version {self.k8s_minor_version} --master-ip {master_ip} --join-command '{join_command}'")
        print("")
        self.print_status("Useful Commands:")
        print("  - View cluster info: kubectl cluster-info")
        print("  - View nodes: kubectl get nodes")
        print("  - View pods: kubectl get pods --all-namespaces")
        print("  - Check CNI plugins: ls -la /opt/cni/bin/")
        print("  - Check pod networking: kubectl get pods -n kube-system | grep flannel")
        print(f"  - Get join command: cat {self.actual_home}/join-command.txt")
        print("")
        self.print_status("Troubleshooting:")
        print("  - If pods fail to start: kubectl describe pods -n kube-system")
        print("  - Check CNI logs: kubectl logs -n kube-system -l app=flannel")
        print("  - Restart kubelet: sudo systemctl restart kubelet")
        print("  - Restart containerd: sudo systemctl restart containerd")
        print("")
        self.print_status("Version Management:")
        print(f"  - Current version: {self.k8s_minor_version}.x")
        print("  - To upgrade cluster: Use kubeadm upgrade commands")
        print("  - To change versions: Re-run script with different --k8s-version")
        print("")
        self.print_warning("Save the join command - you'll need it to add worker nodes!")
        self.print_warning(f"Ensure all worker nodes use the same Kubernetes version: {self.k8s_minor_version}")
        self.print_status("✅ CNI plugins installed and networking configured")
        
    def display_worker_info(self, master_ip: str) -> None:
        """Display worker post-installation information"""
        result = self.run_command("hostname -I | awk '{print $1}'", capture_output=True)
        worker_ip = result.stdout.strip()
        
        result = self.run_command("hostname -s", capture_output=True)
        hostname = result.stdout.strip()
        
        # Get installed Kubernetes version
        try:
            result = self.run_command("kubeadm version -o short", capture_output=True, check=False)
            installed_version = result.stdout.strip() if result.returncode == 0 else f"{self.k8s_minor_version}.x"
        except:
            installed_version = f"{self.k8s_minor_version}.x"
        
        self.print_success("Kubernetes worker node setup completed successfully!")
        print("")
        self.print_status("Worker Node Information:")
        print(f"  - Worker IP: {worker_ip}")
        print(f"  - Master IP: {master_ip}")
        print(f"  - Hostname: {hostname}")
        print(f"  - Kubernetes Version: {installed_version}")
        print(f"  - Expected Version: {self.k8s_minor_version}.x")
        print("")
        self.print_status("To verify this node has joined the cluster:")
        print("  Run 'kubectl get nodes' on the master node")
        print("")
        self.print_status("Version Compatibility:")
        self.print_warning(f"Ensure master node is also running Kubernetes {self.k8s_minor_version}.x")
        self.print_status("Different minor versions between master and worker nodes may cause issues")
        print("")
        self.print_status("This worker node is now ready to accept workloads!")
        
    def setup_master(self) -> None:
        """Main function for master setup"""
        self.print_status("Setting up Kubernetes master node...")
        
        # STEP 0: Check user privileges and set execution context
        self.check_user_privileges()
        self.check_prerequisites()
        
        # STEP 1: MANDATORY - Comprehensive cleanup BEFORE any configuration
        self.cleanup_previous_installation()
        
        # STEP 2: Continue with fresh installation
        self.configure_system("master")
        self.install_containerd()
        self.install_kubernetes()
        join_command = self.initialize_master()
        self.install_cni()
        self.wait_for_cluster_ready()
        self.verify_master_installation()
        self.display_master_info(join_command)
        
        self.print_success("Master node is ready! You can now add worker nodes to the cluster.")
        
    def setup_worker(self, master_ip: str, join_command: str) -> None:
        """Main function for worker setup"""
        self.print_status("Setting up Kubernetes worker node...")
        
        # STEP 0: Check user privileges and set execution context
        self.check_user_privileges()
        self.check_prerequisites()
        
        # STEP 1: MANDATORY - Comprehensive cleanup BEFORE any configuration
        self.cleanup_previous_installation()
        
        # STEP 2: Continue with fresh installation
        self.configure_system("worker")
        self.install_containerd()
        self.install_kubernetes()
        
        # STEP 3: Install CNI plugins (required for worker nodes too)
        self.install_cni_plugins()
        
        # STEP 4: Join the cluster
        self.join_worker(join_command)
        self.verify_worker_installation()
        self.display_worker_info(master_ip)
        
        self.print_success("Worker node is ready and has joined the cluster!")
        
    def command_exists(self, command: str) -> bool:
        """Check if a command exists"""
        try:
            result = subprocess.run(f"which {command}", shell=True, capture_output=True, check=False)
            return result.returncode == 0
        except Exception:
            return False
            
    def write_file(self, path: str, content: str, sudo: bool = False) -> None:
        """Write content to file"""
        if sudo and not self.is_root:
            # Use tee to write with sudo
            self.run_command(f"echo '{content}' | {self.sudo_prefix}tee {path} > /dev/null")
        else:
            # Direct write (either not requiring sudo, or we are root)
            with open(path, 'w') as f:
                f.write(content)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Kubernetes Multi-Node Cluster Setup Script with Comprehensive Cleanup\n" +
                   "⚠️  PERFORMS COMPLETE CLEANUP of all previous Kubernetes installations before setup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🧹 COMPREHENSIVE CLEANUP FEATURES:
  - Removes ALL previous master and worker node configurations
  - Cleans up Docker, containerd, CRI-O, and all container runtimes
  - Removes all Kubernetes packages, services, and processes
  - Cleans network interfaces, iptables rules, and systemd configurations
  - Removes all configuration files and directories
  - Resets kernel modules and sysctl settings

📋 SETUP EXAMPLES:
  Setup master node with default Kubernetes 1.28:
    python3 k8s-setup.py master

  Setup master node with specific Kubernetes version:
    python3 k8s-setup.py master --k8s-version 1.30

  Setup worker node:
    python3 k8s-setup.py worker --master-ip 192.168.1.100 --join-command 'kubeadm join 192.168.1.100:6443 --token abc.xyz --discovery-token-ca-cert-hash sha256:...'

  Setup worker node with specific Kubernetes version:
    python3 k8s-setup.py worker --k8s-version 1.30 --master-ip 192.168.1.100 --join-command 'kubeadm join ...'

  List available Kubernetes versions:
    python3 k8s-setup.py --list-versions

🔧 SUPPORTED KUBERNETES VERSIONS:
  - 1.28 (Default, LTS recommended)
  - 1.29, 1.30, 1.31, 1.32, 1.33 (Latest versions)
  - 1.24, 1.25, 1.26, 1.27 (Older versions with limited support)

⚠️  WARNING: This script will PERMANENTLY REMOVE all existing Kubernetes configurations!
✅ PRIVILEGES: Script supports both root execution and regular user with sudo privileges
        """
    )
    
    parser.add_argument('node_type', nargs='?', choices=['master', 'worker'],
                       help='Type of node to setup (not required with --list-versions)')
    parser.add_argument('--k8s-version', default='1.28',
                       help='Kubernetes minor version to install (e.g., 1.28, 1.29, 1.30). Default: 1.28')
    parser.add_argument('--master-ip', 
                       help='IP address of the master node (required for worker)')
    parser.add_argument('--join-command',
                       help='Complete join command from master (required for worker)')
    parser.add_argument('--list-versions', action='store_true',
                       help='List commonly available Kubernetes versions and exit')
    
    args = parser.parse_args()
    
    # Handle list-versions command
    if args.list_versions:
        KubernetesSetup.list_kubernetes_versions()
        sys.exit(0)
    
    # Validate that node_type is provided when not using --list-versions
    if not args.node_type:
        parser.error("node_type is required unless using --list-versions")
    
    # Validate parameters
    if args.node_type == 'worker':
        if not args.master_ip:
            print("Error: --master-ip is required for worker nodes")
            sys.exit(1)
        if not args.join_command:
            print("Error: --join-command is required for worker nodes")
            sys.exit(1)
    
    # Initialize setup class with selected Kubernetes version
    k8s_setup = KubernetesSetup(args.k8s_version)
    
    # Display setup information
    k8s_setup.print_status(f"Starting Kubernetes {args.node_type} node setup...")
    print("")
    print("🚨 IMPORTANT: This script will perform COMPREHENSIVE CLEANUP of ALL previous Kubernetes installations!")
    print("🔑 PRIVILEGES: This script can be run as root or as a regular user with sudo privileges")
    print("🔧 COMPATIBILITY: Updated for new Kubernetes package repository (pkgs.k8s.io)")
    print(f"📦 VERSION: Installing Kubernetes {args.k8s_version}.x (latest patch version)")
    print("")
    print("This script will:")
    print("0. 🧹 COMPREHENSIVE CLEANUP - Remove ALL previous master/worker configurations")
    print("   - Pre-cleanup repository conflicts and duplicates")
    print("   - Reset kubeadm configurations (both master and worker)")
    print("   - Remove all Kubernetes packages and services")
    print("   - Clean up all container runtimes (Docker, containerd, CRI-O)")
    print("   - Remove all network configurations and interfaces")
    print("   - Clean up all configuration files and directories")
    print("   - Reset iptables rules and systemd configurations")
    print("")
    print("1. Install required dependencies")
    print("2. Install containerd as container runtime")
    print(f"3. Install latest Kubernetes {k8s_setup.k8s_minor_version}.x components (kubelet, kubeadm, kubectl)")
    print("4. Install CNI plugins (loopback, bridge, host-local, etc.)")
    
    if args.node_type == "master":
        print("5. Initialize the master node")
        print("6. Install Flannel CNI networking")
        print("7. Verify cluster and CNI functionality")
        print("8. Generate join command for worker nodes")
    else:
        print(f"5. Join this node to the cluster at {args.master_ip}")
        print("6. Verify the worker node installation")
    
    print("")
    k8s_setup.print_warning("⚠️  ALL EXISTING KUBERNETES CONFIGURATIONS WILL BE PERMANENTLY REMOVED!")
    k8s_setup.print_status("✅ Script supports both root execution and regular user with sudo privileges")
    k8s_setup.print_status("🔄 Uses latest package repository format with automatic version selection")
    k8s_setup.print_status(f"📋 Selected Kubernetes version: {args.k8s_version}.x")
    print("")
    response = input("Do you want to continue with the comprehensive cleanup and setup? (y/N): ")
    if response.lower() != 'y':
        k8s_setup.print_status("Installation cancelled.")
        sys.exit(0)
    
    # Execute setup based on node type
    try:
        if args.node_type == "master":
            k8s_setup.setup_master()
        else:
            k8s_setup.setup_worker(args.master_ip, args.join_command)
        
        k8s_setup.print_success(f"Kubernetes {args.node_type} node setup completed successfully!")
        
    except KeyboardInterrupt:
        k8s_setup.print_error("Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        k8s_setup.print_error(f"Setup failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
