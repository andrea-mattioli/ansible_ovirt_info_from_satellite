# Adding a module locally
Ansible automatically loads all executable files found in certain directories as modules.

Create "modules" path:
```
mkdir -p ~/.ansible/plugins/modules/
```
Copy the module inside modules directory:
```
git clone https://github.com/andrea-mattioli/ansible_ovirt_info_from_satellite.git
mv ansible_ovirt_info_from_satellite/ovirt_info_from_satellite.py ~/.ansible/plugins/modules/
rm -rf ansible_ovirt_info_from_satellite
```
To confirm that ovirt_info_from_satellite is available:
```
ansible-doc -t module ovirt_info_from_satellite
```
