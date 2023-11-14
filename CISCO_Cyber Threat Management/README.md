# CISCO Cyber Threat Management

## "This file should be seen as a simple summary of concepts and useful solutions for the various modules."

Install **Packet Tracer** from [here](https://skillsforall.com/resources/lab-downloads?courseLang=en-US)

Tutorials:

* [Starter](https://skillsforall.com/content/varmir/1.0/m0/course/en-US/assets/1.0.7-packet-tracer---logical-and-physical-mode-exploration.pksz)

* [Diagnostic commands](https://skillsforall.com/content/varmir/1.0/m2/course/en-US/assets/2.1.7-packet-tracer-use-diagnostic-commands.pka)

---

---

## Governance

IT security governance determines who is authorized to make decisions about cybersecurity risks within an organization.

* **data owner**, ensures compliance with policies and procedures, assigns the proper classification to information assets, and determines the criteria for accessing information assets

* **data controller**, determines the purpose for which, and the way in which, personal data is processed

* **data processor**, processes data on behalf of the data controller

* **data custodian**, implements the classification and security controls for the data in accordance with the rules set out by the data owner

* **data steward**, ensures that the data supports an organization's business needs and meets regulatory requirements

* **data protection officer**, oversees an organization's data protection strategy

---

## Types of Security Policies

Every cybersecurity policy is a high-level document that outlines an organization's vision for cybersecurity, including its goals, needs, scope and responsibilities.

* **Identification and Authentication policy**, specifies who should be permitted access to network resources and what verification procedures are in place to facilitate this

* **Password policy**,

* **Acceptable use policy**, highlights a set of rules that determine access to and use of network resources

* **Remote access policy**, sets out how to remotely connect to an organization’s internal network and explains what information is remotely accessible

* **Network maintenance policy**, outlines procedures for updating an organization’s specified operating systems and end-user applications

* **Incident handling policy**

* **Data policy**, sets out measurable rules for processing data within an organization

* **Credential policy**

* **Organizational policy**, provides guidance for how work should be carried out in an organization

---

## Industry Specific laws

* **[FINANCE] Gramm-Leach-Bliley Act GLBA**

* **[CORPORATE ACCOUNTING] Sarbanes-Oxley Act SOX**

* **[CREDIT CARD] Payment Card Industry Data Security Standard PCI DSS**

---

---

# Module 1 Quiz solutions

> What do penetration tests and red team exercises achieve?
> 
> * They simulate attacks to gauge the security capabilities of an organization.

> Cybersecurity professionals may have access to sensitive data. What one 
> factor should they understand to help them make informed ethical 
> decisions in relation to this data?
> 
> * Laws governing the data

> An organization has experienced several incidents involving employees
>  downloading unauthorized software and using unauthorized websites and 
> personal USB devices.
> 
> What measures could the organization implement to manage these threats?
> 
> * Disable USB access, Provide security awareness training, and Use content filtering

> What law protects the privacy of an employee’s personal information from being shared with third parties?
> 
> * GLBA

> Which of the following principles is used by the U.S. government in its access control models?
> 
> * Need to know

> The ability to carry out highly specialized review and evaluation of 
> incoming cybersecurity information to determine if it is useful for 
> intelligence is covered in what category of the National Cybersecurity 
> Workforce Framework?
> 
> * Analyze

> What federal act law would an individual be subject to if they knowingly accessed a government computer without permission?
> 
> * CFAA

> What is the primary goal of IT security governance?
> 
> * To provide oversight to ensure that risks are adequately mitigated

> What act protects the personal information of students in schools?
> 
> * FERPA

> What is the function of the Cloud Security Alliance (CSA)?
> 
> * It provides security guidance to any organization that uses cloud computing.

> Which of the following frameworks identifies controls based on the 
> latest information about common cyber attacks and provides benchmarks 
> for various platforms?
> 
> * CIS

---

---

## Types of Scans

A vulnerability scanner assesses computers, computer systems ,networks or applications for weaknesses.

* **Network scanners**, probe hosts for open ports, enumerate information about users and groups and look for known vulnerabilities on the network

* **Application scanners**, access application source code to test an application

* **Web application scanners**, identify vulnerabilities in web apps

---

* **Intrusive scans**, try to exploit vulnerabilities and may even crash the target

* **Non-intrusive scans**, try not to cause harm to the target

---

* **Credentialed scan**, allow the scanner to harvest more information *(acts as a logged in user)*

* **Non-credentialed scan**, it's an outsider's point of view

---

## Security Automation

* **Security Information and Event Management [SIEM]**, uses log collectors to aggregate log data from sources. Logs can generate many events in a day, SIEM helps reducing the number of events.
  
  *"It identifies internal and external threats, monitors activity and resource usage, conducts compliance reporting for audits and supports incident response"*

* **Orchestration Automation and Response [SOAR]**, allows to collect data about security threats from various sources, and responds to low-level events without the human intervention.
  
  *"It manages threats and vulnerabilities, allows to Security incident response, and Security operations automation"*

---

## Network Testing Tools

* **Nmap / Zenmap**, used to discover computers and their services on a network

* **SuperScan**, port scanning software designed to detect open *TCP* and *UDP* ports, relative services, and to run queries, such as `whoami`, `ping`, `traceroute` and hostname lookups

* **Security Information Event Management [SIEM]**, used in enterprise organizations to provide real time reporting and long-term analysis of security events

* **GFI LANguard**, network and security scanner which detects vulnerabilities

* **Tripwire**, assesses and validates IT configurations against internal policies, compliance standards, and security best practices

* **Nessus**, vulnerability scanner software, focusing on remote access, misconfigurations, and DoS against TCP/IP stack

* **L0phtCrack**, password auditing and recovery application

* **Metasploit**, provides information about vulnerabilities and aids in penetration testing and IDS signature developing

---

## Pentesting

It is a way of testing areas of weaknesses in systems by using various malicious techniques.

**Levels of pentesting:**

* **Black box testing**, the specialist has no knowledge of the inner workings of the system, and attempts to attack it from the *viewpoint of a regular user*
  
  **+ least time consuming            + least expensive**

* **White box testing**, carried out by a specialist with knowledge of how the system works. It emulates a malicious attack by an insider or by someone who has managed to gain such information beforehand, at the recon stage
  
  **- most time consuming             - most expensive**

* **Grey box testing**, it is a combination of white and black testing; specialist has some advantage on the hacking attempts because he has some limited knowledge about the system

**Phases:**

* **Planning**

* **Discovery**

* **Attack**

* **Reporting**

[Wireshark Lab](wiresharklab.html)

### Active reconnaissance

It involves more direct probing and interaction with the target to gather information, potentially including attempting to crack passwords through various means.

### Passive reconnaissance

It gathers information without directly interacting, often leveraging publicly available data.

---

---

# Module 2 Quiz solutions

> What describes a feature of credentialed scans?
> 
> * They return fewer false positives and fewer false negatives.

> What network testing tool is used for password auditing and recovery?
> 
> * L0phtcrack

> An administrator is troubleshooting NetBIOS name resolution on a Windows PC. What command line utility can be used to do this?
> 
> * nbtstat

> What is the purpose of the Tripwire network testing tool?
> 
> * to assess configuration against established policies, recommended best practices, and compliance standards

> An organization has hired a former hacker to test how well the organization would tolerate a real attack by using malicious techniques. What type of testing is the hacker performing for the organization?
> 
> * penetration

> How does network scanning help assess operations security?
> 
> * It can detect open TCP ports on network systems.

> What network scanning tool has advanced features that allows it to use decoy hosts to mask the source of the scan?
> 
> * Nmap

> A new technician was overheard telling colleagues that a secure network password had been discovered through a search of social media sites. What technique was used to acquire the password?
> 
> * passive reconnaissance

> The laptop of an attacker is attached to a corporate network. The attacker is examining all of the network traffic that is passing through the network interface card. Which network reconnaissance method does this scenario describe?
> 
> * sniffing

> Which approach provides automated tools allowing an organization to collect data about security threats from various sources?
> 
> * SOAR

> A new person has joined the security operations team for a manufacturing plant. What is a common scope of responsibility for this person?
> 
> * day-to-day maintenance of network security

> Which penetration test phase is concerned with conducting reconnaissance to gain information about the target network or device?
> 
> * discovery

> Which cybersecurity weapon scans for use of default passwords, missing patches, open ports, misconfigurations, and active IP addresses?
> 
> * vulnerability scanners

---

---

# Threat Intelligence

## Network intelligence communities

* **SANS (SysAdmin, Audit, Network, Security institute)**, contains a large collection of free resources about cybersec research papers, news articles and RISK (discovered attacks and their explanation)

* **Miltre corporation**, maintain a list of common vulnerabilities and exposures **CVEs**

* **FIRST (Forum of Incident Response and Security Teams)** is a security organization that allows cooperation and coordination in information sharing, incident prevention and rapid reaction

* **(ISC)**$^2$ is the International Information Systems Security Certification Consortium that provides vendor neutral education products and career services

* **CIS (Center of Internet Security)**, provides a 24x7 cyber threat warnings ans advisories, vulnerability identification, and mitigation and incident response; It represents a focal point for state, local, tribal, and territorial [SLTT] governments

---

## CISCO Talos

It is a service that allows the exchange of threat information such as vulnerabilities, indicators of compromise (IOC), and mitigation techniques. As threats emerge, threat intelligence services create and distribute firewall rules and ICOs to the devices that have subscribed to the service.

---

## FireEye

It offers SIEM and SOAR with the Helix Security Platform, which uses behavioral analysis and advanced threat detection and is supported by the FireEye Mandiant worldwide threat intelligence network.

---

## Automated Indicator Sharing

It is offered by the U.S. Department of Homeland Security, it enables the real-time exchange of cyber threat indicators between the private sector and the U.S. Federal Government.

---



---

---

# Module 3 Quiz solutions

> What is the primary function of (ISC2)?
> 
> * to provide vendor neutral education products and career services

> What is the primary function of SANS?
> 
> * to maintain the Internet Storm Center

> What is the primary function of the Center for Internet Security (CIS)?
> 
> * to offer 24x7 cyberthreat warnings and advisories, vulnerability identification, and mitigation and incident responses

> What is the primary purpose of the Forum of Incident Response and Security Teams (FIRST)?
> 
> * to enable a variety of computer security incident response teams to collaborate, cooperate, and coordinate information sharing, incident prevention, and rapid reaction strategies

> Which service is offered by the U.S. Department of Homeland Security (DHS) that enables real-time exchange of cyberthreat indicators between the U.S. Federal Government and the private sector?
> 
> * AIS

> What does the MITRE Corporation create and maintain?
> 
> * CVE

> Which threat intelligence sharing open standard specifies, captures, characterizes, and communicates events and properties of network operations?
> 
> * CybOX

> What is the primary objective of a threat intelligence platform (TIP)?
> 
> * to aggregate the data in one place and present it in a comprehensible and usable format

> How does FireEye detect and prevent zero-day attacks?
> 
> * by addressing all stages of an attack lifecycle with a signature-less engine utilizing stateful attack analysis

> Which service is provided by the Cisco Talos Group?
> 
> * collecting information about active, existing, and emerging threats

---

---

# Endpoint Vulnerability Assessment

## Network profiling

Networks, servers, and hosts exhibit typical behavior for a given point in time. Network and device profiling can provide a statistical baseline that serves as a reference point. Unexplained deviations from the baseline may indicate a compromise.

Rises in network utilization during periodic server backup operations is part of normal network functioning and should be part of the baseline data.

Baseline should not include performance data.

A means of capturing just the right period for baseline measurement is known as sliding window anomaly detection; it defines a window that is most representative of network operation and deletes data that is out of date.

Increased utilization of WAN links at unusual times can indicate a network breach and exfiltration of data. Hosts that begin to access obscure internet servers, resolve domains that are obtained through dynamic DNS, or use protocols or services that
 are not needed by the system user can also indicate compromise. Deviations in network behavior are difficult to detect if normal behavior is not known.

**Tools for characterize normal network traffic:**

* **NetFlow**

* **Wireshark**

| Network profile element          | Description                                                                                 |
| -------------------------------- | ------------------------------------------------------------------------------------------- |
| **Session duration**             | time between the establishment of a data flow and its termination                           |
| **total Throughput**             | amount of data passing from a given source to a given destination in a given period of time |
| **Ports used**                   | list of TCP or UDP that are available                                                       |
| **Critical asset address space** | IP addresses or the logical location of essential systems or data                           |

A user who suddenly begins logging in to the network at strange times from a remote location should raise alarms if this behavior is a deviation from a known norm.

---

## Server profiling

A server profile is a security baseline for a given server. It establishes the network, user, and application parameters that are accepted for a specific server.

To establish the server profile, we need to understand the function that a server is intended to perform in a network.

| Server profile element           | Description                                                                          |
| -------------------------------- | ------------------------------------------------------------------------------------ |
| **Listening ports**              | The TCP and UDP deamons and ports that are normally allowed to be open on the server |
| **Logged in users and accounts** | Parameters defining user access and behavior                                         |
| **Service accounts**             | Type of service that an application is allowed to run                                |
| **Software environment**         | Tasks, processes, and applications that are permitted to run on the server           |

---

## Network Anomaly Detection

Network behavior is described by a large amount of diverse data such as the packet flow, features of the packets themselves, and telemetry fro multiple sources.

**Network Behavior Analysis [NBA]** is the analysis of this diverse, unstructured data using big data analytics techniques. It uses sophisticated statistical and machine learning techniques to compare normal performance baselines with network performance at a given time.

---

## Network Vulnerability Testing

* **Risk Analysis**, analysts evaluate the risk posed by vulnerabilities to a specific organization; it includes assessment of the likelihood of attacks, identifies types of likely threat actors, and evaluates the impact of successful exploits on the organization
  
  * carried out by internal or external consultants, risk management frameworks

* **Vulnerability Assessment**, this test employs software to scan internet facing servers and internal networks for various types of vulnerabilities. These vulnerabilities include unknown infections, weaknesses in web-facing database services, missing software patches, unnecessary listening ports, etc.
  
  * Openvas, Microsoft, Baseline Analyzer, Nessus, Qualys, Nmap

* **Penetration testing**
  
  * Metasploit, CORE Impact, ethical hackers

---










































