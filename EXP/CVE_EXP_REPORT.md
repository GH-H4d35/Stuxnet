# Stuxnet — Exploited Vulnerabilities

# Overview

Stuxnet is a computer worm discovered in 2010. It targeted industrial control systems, specifically Siemens SIMATIC WinCC / STEP 7 environments. The worm leveraged multiple vulnerabilities across Windows and Siemens software to achieve initial infection, privilege escalation, lateral movement, and payload execution.

#.Microsoft Windows Vulnerabilities

**CVE-2010-2568 (MS10-046)**

Windows Shell shortcut (.lnk) parsing vulnerability. Allows remote code execution when a user views a malicious shortcut file. Stuxnet used this as the primary initial infection vector via removable USB drives. The crafted .lnk file caused Windows to load a malicious DLL without user interaction.

**CVE-2010-2729 (MS10-061)**

Windows Print Spooler service impersonation vulnerability. Allows a local attacker to execute code with system privileges. Stuxnet used this for lateral movement across networked machines by writing a malicious file to the print spooler directory.

**CVE-2008-4250 (MS08-067)**

Windows Server Service RPC remote code execution vulnerability. Allows remote code execution over SMB. Stuxnet exploited this to propagate across local networks without user interaction.

**CVE-2010-3888**

Windows Task Scheduler privilege escalation vulnerability. Allows a local user to elevate privileges to SYSTEM level. Used by Stuxnet to gain higher integrity on infected hosts.

**CVE-2010-2743**

Windows Win32k keyboard layout privilege escalation vulnerability. Allows a local attacker to run arbitrary code in kernel mode. Used by Stuxnet for local privilege escalation.

#.Siemens Vulnerabilities

**CVE-2010-2772**

Siemens SIMATIC WinCC and PCS 7 hardcoded database password vulnerability. The default password for the WinCC SQL Server instance was hardcoded and publicly known. Stuxnet used this to access the backend database and inject malicious code into process control routines.

**CVE-2012-3015**

Siemens SIMATIC STEP 7 DLL hijacking vulnerability. Allows a malicious DLL placed in a project directory to be loaded by the STEP 7 application. Stuxnet used this to execute its payload within the engineering workstation environment.

#.Summary Table

CVE Vendor Component Purpose
CVE-2010-2568 Microsoft Windows Shell Initial infection via USB
CVE-2010-2729 Microsoft Print Spooler Lateral movement
CVE-2008-4250 Microsoft Server Service RPC Network propagation
CVE-2010-3888 Microsoft Task Scheduler Privilege escalation
CVE-2010-2743 Microsoft Win32k Kernel privilege escalation
CVE-2010-2772 Siemens WinCC / PCS 7 Database access and payload injection
CVE-2012-3015 Siemens STEP 7 DLL hijacking and execution
