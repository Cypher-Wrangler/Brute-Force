## 🚀 Brute-Force
<p align="center">This project identify a common credential access technique via Brute Force on a Windows machine, using Splunk for quering and creating transforming commands
to enhance analysis.</p>
# Looking at MITRE ATT&CK framework to understand why attackers perform brute force attack
<p align="center">
  <img src="https://github.com/user-attachments/assets/f2ee01d2-156a-4fc0-834e-ac0efb5dc507" />
</p>
- When we think about brute force activity, we should immediately think about failed login attempts due to repetitve password guessing. Windows generates a failed login attempt Event ID 4625 under security log.

```spl
 index=mitre EventCode=4625
```
<p align="center">
  <img src="https://github.com/user-attachments/assets/7d018cf2-f8ce-4578-b414-52c5f69c72b4" />
</p>
- This shows we have 101 failed login attempts.
- Looking at user field for valid acccount, administrator has more failed authentication making it an account of interest;
 <p align="center">
  <img src="https://github.com/user-attachments/assets/486960a6-5eb4-4d65-bcbc-b92dc062f85f" />
</p>
- Creating a transforming command pick interesting fields that will query; which user failing to login, what computer is trying to login to and where this login is sourcing from.
```spl
  index=mitre EventCode=4625 | stats count by _time, user, ComputerName, src_ip
```
 <p align="center">
  <img src="https://github.com/user-attachments/assets/4cbc817d-e586-4fc6-97c1-7bf5226dfaa1" />
/>
</p>
- **From the stastics looking at the src_ip field values, these are mainly coming from 192.168.100.181. This a good chance to look at the company asset list to see what this IP belongs to. There could be some 'legimate' purpose such as a red team engagement or maybe a vulnerability scanner, but nonetheles, we should continue to investigate.**
- Since the administrator account had the most failed authentication we can look if it had its password changed recently, as this could be a forgotten password factor:
``` spl
   index=mitre EventCode 4723 OR 4724 use=administrator
```
 <p align="center">
  <img src="https://github.com/user-attachments/assets/ed7eba07-f293-4359-83d3-f6fb143e8d4b" />
</p>
- It shows zero events showing administratr didnt change their password recently in a production environment search for 7 or 30 days of data.

# Cleanup
- we can further clean our results by group using values;
``` spl
 index=mitre EventCode=4625 | stats values(user) count by ComputerName, src_ip
```
<p align="center">
  <img width="1075" height="775" alt="Screenshot 2025-12-01 095717" src="https://github.com/user-attachments/assets/4ca15343-612d-4c4c-97c6-568f4f5d30b6" />
</p>
- Now we have users grouped by source IP and Computers. We see 192.168.100.181 has a large list of users that it attempted to login with.
- In an scenario with a large number of users we can use distint count command to automatically count the individual users;
```spl
    index=mitre EventCode=4625 | stats values(user) dc{user} count by _time, ComputerName, src_ip
```
<p align="center">
 <img width="1069" height="1078" alt="image" src="https://github.com/user-attachments/assets/e7ba28a9-fa4b-4ced-9e2b-2b299e90ebcb" />
</p>
- The _time field shows when these authentication attempts took place.
- From this analysis some attempts took place within seconds and used more than 1 user account. This is a clear indication of a password spray attack, which is a sub-technique of Brute Force.
<p align="center">
 <img width="1059" height="1068" alt="image" src="https://github.com/user-attachments/assets/851bae41-4a32-4b92-aa45-1e6b4be7bf1e" />
</p>

# Looking at the administrator account which had more failed attempts
- Point at this account along with source IP to see how many hits are there;
  ``` spl
   index=mitre EventCode=4625 user=administrator src_ip=192.168.100.81 | stats count by _time src_ip, user
  ```
  <p align="center"
  <img width="1079" height="758" alt="image" src="https://github.com/user-attachments/assets/c873a967-faf7-437d-bff6-c10cd6b7e2de" />
  </p>
- Looking at the entire activity of this user within a minute theres 82 events sourcing from 192.168.100.181 meaning its likely targeted from a brute force attack.
# Successful attempts
- Next we can look if there was any successful login from this source IP
- Use EventCode 4624 for successful logins
```spl
index=mitre EventCode=4624 src_ip=192.168.100.181 | stats count by _time, user, src_ip
```
<p align="center">
<img width="1062" height="873" alt="image" src="https://github.com/user-attachments/assets/7da80a9a-8e37-48c6-87f0-71200e554e9f" />
</p>
- we can see theres successful logins from administrator and sm account

# Takeaways.
- From failed logins we can see if theres attempt to access the environment using valid accounts
- Looking at where those attempts are being sourced from can been a quick win for identifying evil
- Look for password changes or reset as this can be a reason for failed login attempts.
- Use the login ID to see other activities performed during that session
- Looking at user agents can give a sense of where and how a user typically authenticates
- Look for process creations 



    
