# EventSecurity

![image](https://github.com/user-attachments/assets/b52ba1fb-f322-46f7-b77f-5b1018a02390)

App to to scan Windows Event Viewer defined in EventSecurity.json (app configuration), when the logs matches that are detected exceed threshold, the IP Address is blocked using Windows Firewall
```
{
  "Interval": 30,
  "Threshold": 5,
  "Configs": {
    "MSSQL": {
      "EventId": 18456,
      "EventType": "Application",
      "Message": "Login failed for user"
    },
    "RDP": {
      "EventId": 4625,
      "EventType": "Security",
      "Message": "An account failed"
    }
  }
}
```
