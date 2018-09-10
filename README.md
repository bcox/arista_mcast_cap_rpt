# arista_mcast_cap_rpt
  Tool to capture and report on multicast flows on a Arista device

### returns the following format
```
  Source: 10.10.10.1, Group: 239.0.0.1
  Captured 50 packets, size min/max/avg: 78/78/78, pps: 10.0
  data flows: (trans,source,port->dest,port tos: <tos/cs/dscp> count: <n>)
  UDP,10.10.10.1,3033->239.0.0.1,62061 tos: 0/0/0': 50
```

### log messages created
```
  Jun 29 13:47:35 wa488 FastCapi: 1038: %SYS-5-CONFIG_E: Enter configuration mode from console by local_command_api on command-api (unix:)
  Jun 29 13:47:35 wa488 FastCapi: 1039: %SYS-5-CONFIG_I: Configured from console by local_command_api on command-api (unix:)
  Jun 29 13:47:40 wa488 FastCapi: 1040: %SYS-5-CONFIG_E: Enter configuration mode from console by local_command_api on command-api (unix:)
  Jun 29 13:47:41 wa488 FastCapi: 1041: %SYS-5-CONFIG_I: Configured from console by local_command_api on command-api (unix:)
```
