# kubernetes

# Run the master setup with CNI fixes
```
python3 k8s-setup.py master --k8s-version 1.28
```
# For worker nodes (also gets CNI plugins now)
```
python3 k8s-setup.py worker --k8s-version 1.28 --master-ip MASTER_IP --join-command 'COMMAND'
```
