## 🚀 Brute-Force
<p align="center">This project identify a common credential access technique via Brute Force on a Windows machine, using Splunk for quering and creating transforming commands
to enhance analysis.</p>
# Looking at MITRE ATT&CK framework to under why attackers perform brute force attack
<p align="center">
  <img src="https://github.com/user-attachments/assets/f2ee01d2-156a-4fc0-834e-ac0efb5dc507" />
</p>
- When we think about brute force activity, we should immediately think about failed login attempts due to repetitve password guessing. Windows generates a failed login attempt Event ID 4625 under security log.

```spl
 index=mitre EventCode=4625
```
