# os-notifications
OPNsense notifications in MAX, Telegram, and Gotify

**Compatibility:** для OPNsense 26.7.x

System resource alerts depend on existing health checks, such as those configured in Monit. Network, security, Dynamic DNS and other service alerts are read from their own journals. Separate optional health checks read system measurements or local files without altering services.

| Notification |	When it is sent |
|---|---|
|System health problems |	A configured health check reports high CPU or memory usage, a full disk or a failed monitored service. |
|Disk health and SSD wear	| SMART health failure, high NVMe lifetime usage or drive overheating (requires smartctl). |
|Swap and firewall resources |	Swap, firewall state table or mbuf usage reaches its configured percentage. |
|Firewall Alias updates	| A URL Table download is empty, missing or out of date. |
| Certificate expiry	| A monitored local certificate expires in 30, 7, 1 or 0 days. |
| Local backup freshness	| No recent local configuration snapshot exists in the selected folder. |
| CPU temperature alerts	| The hottest detected CPU core exceeds your limit twice; after cooling 5 °C below the limit for two readings, a recovery message is sent. |
| System health recovered	| The monitored resource or service returns to a healthy state. |
| Monitored service actions	| A health check logs starting, stopping or restarting a process. |
| Other check changes	| A monitoring check changes state without a clear failure or recovery. |
| System started	| OPNsense finishes startup. Delivery may be retried if the network is not yet ready. |
| System shutdown or restart	| OPNsense starts a normal shutdown or reboot, while the network is still available. |
| Gateway connection status	| A WAN gateway goes offline or becomes reachable again. |
| Gateway latency and packet loss	| Monitoring reports degraded WAN connectivity. |
| Administrator and SSH logins	| An administrator signs in or an authentication attempt fails. |
| CrowdSec security and errors	| CrowdSec logs a blocking decision or a service problem. |
| VPN and DNS	| A VPN disconnects or a DNS service reports a fault. |
| Dynamic DNS	| A DNS record is updated or the provider rejects an update. |
| Firewall block summaries	| At least ten blocked packets are logged in five minutes. |


**Examples of notifications**

<img width="507" height="202" alt="image" src="https://github.com/user-attachments/assets/81f4e44a-12bc-45a0-b11a-de675af3423f" />

<img width="510" height="283" alt="image" src="https://github.com/user-attachments/assets/c89185a7-3715-4d1b-b20c-f436b5e64b98" />

<img width="517" height="367" alt="image" src="https://github.com/user-attachments/assets/693f1728-3f05-412c-bd7a-329945b3e2d2" />

<img width="373" height="187" alt="image" src="https://github.com/user-attachments/assets/5a9643bc-de67-48c3-9fd2-f9f45c31368c" />

<img width="510" height="205" alt="image" src="https://github.com/user-attachments/assets/8425f0c9-8614-4116-a1e8-80bfe180cf67" />

<img width="508" height="287" alt="image" src="https://github.com/user-attachments/assets/38ce7da3-4139-4bf1-aaa2-459f11f92d8e" />


