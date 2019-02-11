# ACI2SWATCH
This script does read Global Endpoints from Cisco ACI and pushing them as Host Groups into Cisco Stealthwatch. 

Interval of updating Stealthwacth can be configured via the config-file. 

Tested on:
  APIC: 4.0(1h)
  Stealthwatch: 7.0
  
## Manual Installation
First thing is to create a folder-structure to hold the config-file and the actual python scripts.

This creates a folder "aci2swatch" plus the folder to store the logs:
```mkdir -p aci2swatch/log```

Put the scripts into "aci2swatch" and got to this folder.
```cd aci2swatch```

## Installation with Git
Clone the Repo
```git clone https://github.com/b0066365/aci2swatch.git```

Move to the directory
```cd aci2fmc```

## Config-File

Create the Config-File
```vi config.cfg```

``` INI
[GLOBAL]
UPDATE_INTERVAL=60
LOG_FILE=/mnt/scripts/swatch/log/aci2swatch.log
LOG_DIR=/mnt/scripts/swatch/log
# Levels: debug, info, warning, critical, error, | Default: warning
LOG_LEVEL=info

[APIC]
APIC_IP=<IP/NAME>
APIC_USER=admin
APIC_PASSWORD=<BASE64 Encoded PASSWORD>

[SWATCH]
SWATCH_IP=<IP/NAME>
SWATCH_USER=admin
SWATCH_PASSWORD=<BASE64 Encoded PASSWORD>
SWATCH_PREFIX=APIC_
SWATCH_PARENTGROUP=From ACI
SWATCH_HOSTBASELINES=True
```

### Stealthwatch - Parent Group
This option in the config-file let you specifiy the parent group in which the ACI Objects get created. 

``` INI
SWATCH_PARENTGROUP=From ACI
```
Make sure this group exists before starting the script. Any pre-defined group in Stealthwatch can be used.




## Docker 
In the same directory, now run the following command:
```docker-compose up```

It will pull the right container, mount the local directory into the contianer and start the script.

Check Stealthwatch for the newly created hostgroups.