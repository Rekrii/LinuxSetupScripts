#!/bin/bash

# Function to prompt for input with a default value
prompt() {
    local prompt_text=$1
    local default_value=$2
    read -p "$prompt_text [$default_value]: " input
    echo "${input:-$default_value}"
}

# Function to convert CIDR to netmask
cidr_to_netmask() {
    local cidr=$1
    local mask=$(( (1 << 32) - (1 << (32 - cidr)) ))
    printf "%d.%d.%d.%d\n" $(( (mask >> 24) & 255 )) $(( (mask >> 16) & 255 )) $(( (mask >> 8) & 255 )) $(( mask & 255 ))
}

# Notify user about apt update and upgrade
echo "This script will perform an apt update and upgrade. Please run this script as root."

echo "Doing pre-run apt update..."
apt update
echo "Done."

echo "Installing ipcalc for CIDR to netmask conversion..."
apt install -y ipcalc
echo "Done."

# Ask if the user wants to schedule a monthly cron job for apt update and upgrade and reboot
add_schedule=$(prompt "Do you want to schedule a monthly (1st at 2:00 AM) cron job for apt update and upgrade and reboot? (yes/no)" "no")
if [ "$add_schedule" == "yes" ]; then
    # Add a cron job to run apt update and upgrade and reboot on the 1st of every month at 2:00 AM
    cronjob="0 2 1 * * root sh -c 'apt update && apt upgrade -y && reboot'"
    echo "Adding the following cron job to /etc/crontab:"
    echo "$cronjob"
    echo "$cronjob" >>/etc/crontab
fi

ip_type=$(prompt "Set IP Type IP (static/DHCP)" "DHCP")
# if ip_type is not DHCP, then prompt for netmask, gateway, and DNS servers
if [ "$ip_type" != "DHCP" ]; then
    # List all non-loopback interfaces with IPv4 addresses
    mapfile -t iface_info < <(
        ip -o -4 addr show | awk '!/ lo / {print NR ") " $2 " - " $4}'
    )
    echo "Available network interfaces with assigned IPv4 addresses:"
    for idx in "${!iface_info[@]}"; do
        info="${iface_info[$idx]}"
        iface=$(echo "$info" | awk '{print $2}')
        ip_cidr=$(echo "$info" | awk '{print $4}')
        ip_addr=$(echo "$ip_cidr" | cut -d/ -f1)
        cidr=$(echo "$ip_cidr" | cut -d/ -f2)
        # Convert CIDR to netmask using the function
        netmask=$(cidr_to_netmask "$cidr")
        gateway=$(ip route | awk -v dev="$iface" '$0 ~ "default" && $0 ~ dev {print $3; exit}')
        echo "$((idx + 1))) Interface: $iface"  # Start from 1
        echo "    IP: $ip_addr"
        echo "    Netmask: $netmask"
        echo "    Gateway: ${gateway:-Not found}"
    done
    echo "$(( ${#iface_info[@]} + 1 )) Manual entry"

    read -p "Select the interface to use (1-${#iface_info[@]}, or $(( ${#iface_info[@]} + 1 )) for manual): " iface_choice

    if [[ "$iface_choice" =~ ^[0-9]+$ ]] && [ "$iface_choice" -ge 1 ] && [ "$iface_choice" -le "${#iface_info[@]}" ]; then
        selected_info="${iface_info[$((iface_choice-1))]}"
        eth_iface_name=$(echo "$selected_info" | awk '{print $2}')
        ip_cidr=$(echo "$selected_info" | awk '{print $4}')
        static_ip=$(echo "$ip_cidr" | cut -d/ -f1)
        cidr=$(echo "$ip_cidr" | cut -d/ -f2)
        netmask=$(cidr_to_netmask "$cidr")
        gateway=$(ip route | awk -v dev="$eth_iface_name" '$0 ~ "default" && $0 ~ dev {print $3; exit}')
        # Fetch DNS servers
        current_dns=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | sort -u | tr '\n' ' ')
        dns_servers=$(prompt "Set DNS servers" "$current_dns")
    else
        eth_iface_name=$(prompt "Enter interface name" "")
        static_ip=$(prompt "Set static IP" "")
        netmask=$(prompt "Set netmask" "")
        gateway=$(prompt "Set gateway" "")
        dns_servers=$(prompt "Set DNS servers" "")
    fi
fi

hostname=$(prompt "Set hostname" "$(hostname)")
max_auth_tries=$(prompt "Set sshd MaxAuthTries" "12")
sshkey_file_path=$(prompt "Load sshkey data from path" "None")
# if sshkey_file_path is not None, then check if the path exists and allow the user to re-enter the path
file_count=$(ls $sshkey_file_path 2>/dev/null | wc -l)
if [ "$sshkey_file_path" != "None" ]; then
    if [ $file_count -eq 0 ]; then
        echo "Key not found on given path: $sshkey_file_path"
        sshkey_file_path=$(prompt "Load sshkey data from path" "None")
        file_count=$(ls $sshkey_file_path 2>/dev/null | wc -l)
    fi
fi

# Prompt for sudo installation and user setup
install_sudo=$(prompt "Install and set up sudo (yes/no)" "yes")
# get the first non-root, non-nobody user to set up sudo for
non_root_user=$(awk -F: '$3>999 && $1 != "nobody" {print $1}' /etc/passwd)
sudo_user=$(prompt "Setup sudo for user" "$non_root_user")

# Print to the user all changes that will be made
echo ""
echo "The following changes will be made:"

if [ "$ip_type" != "DHCP" ]; then
    echo "   - Set IP type to static"
    echo "   - Set static IP to $static_ip"
    echo "   - Set netmask to $netmask"
    echo "   - Set gateway to $gateway"
    echo "   - Set DNS servers to $dns_servers"
# else print that it's DHCP
else
    echo "   - Set IP type to DHCP"
fi

if [ "$hostname" != "$(hostname)" ]; then
    echo "   - Set hostname to $hostname"
fi

echo "   - Set sshd MaxAuthTries to $max_auth_tries"

if [ "$sshkey_file_path" != "None" ]; then
    if [ $file_count -eq 1 ]; then
        echo "   - Load SSH key data from $sshkey_file_path"
    else
        echo "SSH key path $sshkey_file_path does not exist"
    fi
else
    echo "   - No SSH key data will be loaded"
fi

if [ "$install_sudo" == "yes" ]; then
    echo "   - Install and set up sudo"
    echo "   - Setup sudo for user $sudo_user"
fi

echo "   - Ensure the sshd service is installed and running"

echo "   - Perform apt update and upgrade"

read -p "Do you want to continue? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Exiting script"
    exit 1
fi

# Update and upgrade the system
apt update && apt upgrade -y

# Ensure the sshd service is installed and running
apt install -y openssh-server
systemctl enable sshd
systemctl start sshd
# Ensure the sshd service is running
if [ "$(systemctl is-active sshd)" != "active" ]; then
    echo "sshd service is not running. Exiting script."
    exit 1
fi

# Set static IP if specified
if [ "$ip_type" != "DHCP" ]; then
    cat <<EOF | tee /etc/network/interfaces.d/static_ip.cfg
auto eth0
iface eth0 inet static
    address $static_ip
    netmask $netmask
    gateway $gateway
    dns-nameservers $dns_servers
EOF
    systemctl restart networking.service
fi

# Set hostname if specified
if [ "$hostname" != "$(hostname)" ]; then
    echo "Setting hostname to $hostname"
    hostnamectl set-hostname "$hostname"
fi

# Set sshd MaxAuthTries
echo "Setting sshd MaxAuthTries to $max_auth_tries"
sed -i "s/^#*MaxAuthTries.*/MaxAuthTries $max_auth_tries/" /etc/ssh/sshd_config
systemctl restart sshd.service

# Install sudo if specified
if [ "$install_sudo" == "yes" ]; then
    echo "Installing sudo"
    apt install -y sudo
    # make sure sudo group exists
    if [ $(cat /etc/group | grep -c "^sudo") -eq 0 ]; then
        groupadd sudo
    fi
    echo "Setting up sudo for user $sudo_user"
    usermod -aG sudo "$sudo_user"
    # update the sudoers file to allow sudo group to have sudo privileges
    has_sudo=$(cat /etc/sudoers | grep -c "sudo ALL=(ALL:ALL) ALL")
    has_commented_sudo=$(cat /etc/sudoers | grep -c "%sudo ALL=(ALL:ALL) ALL")
    if [ $has_sudo -eq 0 ]; then
        if [ $has_commented_sudo -eq 1 ]; then
            sed -i "s/^%sudo ALL=(ALL:ALL) ALL/sudo ALL=(ALL:ALL) ALL/" /etc/sudoers
        else
            echo "sudo ALL=(ALL:ALL) ALL" | tee -a /etc/sudoers
        fi
    fi
    # Add the user to the sudoers file if it isn't already there
    if [ $(cat /etc/sudoers | grep -c "$sudo_user ALL=(ALL:ALL) ALL") -eq 0 ]; then
        echo "$sudo_user ALL=(ALL:ALL) ALL" | tee -a /etc/sudoers
    fi
fi

# Load SSH key data from specified path
if [ "$sshkey_file_path" != "None" ] && [ $file_count -eq 1 ]; then
    echo "Loading SSH key data from $sshkey_file_path"
    # update the user's authorized_keys file with the key data
    mkdir -p /home/$sudo_user/.ssh
    # make sure the key isn't already in the authorized_keys file
    touch /home/$sudo_user/.ssh/authorized_keys
    if [ $(grep -c "$(cat $sshkey_file_path)" /home/$sudo_user/.ssh/authorized_keys) -eq 0 ]; then
        cat "$sshkey_file_path" >> /home/$sudo_user/.ssh/authorized_keys
    fi
    # update the .ssh folder permissions
    chmod 700 /home/$sudo_user/.ssh
    # update the authorized_keys file permissions
    chmod 600 /home/$sudo_user/.ssh/authorized_keys
    # update the authorized_keys file ownership
    chown -R $sudo_user:$sudo_user /home/$sudo_user/.ssh
    # enable PubkeyAuthentication and AuthorizedKeysFile in sshd_config
    sed -i "s/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/" /etc/ssh/sshd_config
    sed -i "s/^#*AuthorizedKeysFile.*/AuthorizedKeysFile .ssh\/authorized_keys/" /etc/ssh/sshd_config
    systemctl restart sshd
else
    echo "SSH key path $sshkey_file_path does not exist"
fi

echo "Configuration changes completed."
