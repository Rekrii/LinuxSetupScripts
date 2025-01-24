# LinuxSetupScripts

Used for home VM setup to automate simple tasks.

## Debian 12 Setup Script

This script will help you set up a Debian 12 system with the following configurations:
- Update and upgrade the system
- Set a static IP address
- Set the hostname
- Configure SSH MaxAuthTries
- Install Python 3.13
- Load SSH key data
- Install and set up sudo
- Schedule a monthly cron job for apt update and upgrade and reboot
- Ensure the sshd service is installed and running

## Usage

Run the script as root and follow the prompts:

```bash
sudo ./debian_12_setup.sh
```

If sudo is not installed, you can run the script directly as root:

```bash
su -c ./debian_12_setup.sh
```

## Setting a Static IP

If you choose to set a static IP, the script will configure the network interface with the provided IP address. Make sure to provide the correct IP address, netmask, gateway, and DNS servers when prompted.

## Installing and Setting Up Sudo

The script will install sudo if it is not already installed and configure sudo for a specified user. Make sure to provide the correct username when prompted. The user will also be added to the sudoers file.

## Scheduling a Cron Job

The script will prompt you to schedule a monthly cron job for apt update and upgrade and reboot. If you choose to do so, the cron job will be added to `/etc/crontab`.

## Ensuring the sshd Service is Installed and Running

The script will ensure that the sshd service is installed, enabled, and running.

## Loading SSH Key Data

The script will load SSH key data from a specified path into the user's `authorized_keys` file. Make sure to provide the correct path when prompted.
