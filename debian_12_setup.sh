#!/bin/bash

# Function to prompt for input with a default value
prompt() {
    local prompt_text=$1
    local default_value=$2
    read -p "$prompt_text [$default_value]: " input
    echo "${input:-$default_value}"
}

# Notify user about apt update and upgrade
echo "This script will perform an apt update and upgrade. Please run this script as root."

# ifconfig don't come pre-installed on Debian 12, so ask to install it
if [ ! -x "$(command -v ifconfig)" ]; then
    install_ifconfig=$(prompt "[Optional] net-tools is used to show network information. Do you want to install it? (yes/no)" "no")
    if [ "$install_ifconfig" == "yes" ]; then
        apt install -y net-tools
    fi
fi

# Ask if the user wants to schedule a monthly cron job for apt update and upgrade and reboot
add_schedule=$(prompt "Do you want to schedule a monthly (1st at 2:00 AM) cron job for apt update and upgrade and reboot? (yes/no)" "no")
if [ "$add_schedule" == "yes" ]; then
    # Add a cron job to run apt update and upgrade and reboot on the 1st of every month at 2:00 AM
    cronjob="0 2 1 * * root apt update && apt upgrade -y && reboot"
    echo "Adding the following cron job to /etc/crontab:"
    echo "$cronjob"
    echo "$cronjob" >>/etc/crontab
fi

# Prompt for inputs
ip_type=$(prompt "Set IP Type IP (static/DHCP)" "DHCP")
# if ip_type is not DHCP, then prompt for netmask, gateway, and DNS servers
if [ "$ip_type" != "DHCP" ]; then
    # use the first eth interface to get the current IP, netmask, gateway, and DNS servers
    eth_iface_name=$(ip link | grep 'state UP' | awk '{print $2}' | tr -d ':')
    current_ip=$(hostname -I | awk '{print $1}')
    current_netmask=$(ifconfig $eth_iface_name | grep 'inet ' | grep -v ') ' | awk '{print $4}')
    current_gateway=$(ip route | grep default | awk '{print $3}')
    # fetch the DNS servers from /etc/resolv.conf and deduplicate them
    current_dns=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}' | sort | uniq | tr '\n' ' ')

    static_ip=$(prompt "Set static IP" "$current_ip")
    netmask=$(prompt "Set netmask" "$current_netmask")
    gateway=$(prompt "Set gateway" "$current_gateway")
    dns_servers=$(prompt "Set DNS servers" "$current_dns")
fi

hostname=$(prompt "Set hostname" "$(hostname)")
max_auth_tries=$(prompt "Set sshd MaxAuthTries" "12")
install_python=$(prompt "Install Python 13" "yes")
sshkey_file_path=$(prompt "Load sshkey data from path" "None")
# if sshkey_file_path is not None, then check if the path exists and allow the user to re-enter the path
file_count=$(ls $sshkey_file_path | wc -l)
if [ "$sshkey_file_path" != "None" ]; then
    if [ $file_count -eq 0 ]; then
        echo "Key not found on given path: $sshkey_file_path"
        sshkey_file_path=$(prompt "Load sshkey data from path" "None")
        file_count=$(ls $sshkey_file_path | wc -l)
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

if [ "$install_python" == "yes" ]; then
    echo "   - Install Python 3.13"
fi

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

# Install Python 3.13 if specified and install it from deadsnakes PPA
if [ "$install_python" == "yes" ]; then
    echo "Installing Python 3.13"
    echo "deb http://deb.debian.org/debian testing main contrib non-free" > /etc/apt/sources.list.d/python313.list

    # Create a preferences file to pin the testing repository
    cat <<EOF > /etc/apt/preferences.d/python313
Package: *
Pin: release a=stable
Pin-Priority: 900

Package: python3.13
Pin: release a=testing
Pin-Priority: 500
EOF

    apt-get update
    apt-get install -y -t testing python3.13
fi

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
    # Add the user to the sudoers file if it isnt already there
    if [ $(cat /etc/sudoers | grep -c "$sudo_user ALL=(ALL:ALL) ALL") -eq 0 ]; then
        echo "$sudo_user ALL=(ALL:ALL) ALL" | tee -a /etc/sudoers
    fi
fi

# Load SSH key data from specified path
if [ "$sshkey_file_path" != "None" ] && [ $file_count -eq 1 ]; then
    echo "Loading SSH key data from $sshkey_file_path"
    # update the users authorized_keys file with the key data
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