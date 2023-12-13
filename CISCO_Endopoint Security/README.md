# CISCO Endpoint Security

## "This file should be seen as a simple summary of concepts and useful solutions for the various modules."

Install **Packet Tracer** from [here](https://skillsforall.com/resources/lab-downloads?courseLang=en-US)

Tutorials:

* [Starter](https://skillsforall.com/content/varmir/1.0/m0/course/en-US/assets/1.0.7-packet-tracer---logical-and-physical-mode-exploration.pksz)

## Threats

* **Software attacks**, a successful denial-of-service [DoS attack] or a computer virus

* **Software errors**, bugs, an application going offline or a cross-site script or illegal file server share

* **Sabotage**, an authorized user successfully penetrating and compromising an organization's primary database or the defacement of an organization's website

* **Human error**, inadvertent data entry errors or a firewall misconfiguration

* **Theft**, devices being stolen from an unlocked room

* **Hardware failures**

* **Utility interruption**, electrical power outages or water damage resulting from sprinkler failure

* **Natural disasters**

## Internal Vs External Threats

**Internal threats** are usually carried out by current or former employees and other contract partners.

**External threats** typically stems from amateur or skilled attackers

## User Threats and Vulnerabilities

A **User domain** includes anyone with access to an organization's information system. Users are considered the weakest link in information security systems.

* **No awareness of security**
  
  Users must be aware of and understand an organization's sensitive data, security policies and procedures.

* **Poorly enforced security policies**
  
  Security policies must be known be all the users.

* **Data theft**

* **Unauthorized downloads and media**
  
  Users must not download from the web or from removable devices.

* **Unauthorized virtual private network [VPNs]**
  
  Users must not use VPNs.

* **Unauthorized websites**

* **Destruction of systems, applications or data**
  
  Activists or competitors can delete or destroy data and devices.

---

### Backdoor

Backdoor programs such as Netbus and Back Orifice, are used by cyber criminals to gain unauthorized access to a system by bypassing the normal authentication procedures.

Users inside the organization must run a **remote administrative tool program [RAT]** in order to install the backdoor.

### Rootkit

It modifies the operating system to create a backdoor, which attackers can then use to access the computer remotely.

Using privilege escalation they can modify all kinds of system files and also system forensics and monitoring tools.

---

## Social Engineering

It is a non-technical strategy that attempts to manipulate individuals into performing certain actions or divulging confidential information.

* **Pretexting**, an individual lies to gain access to privileged data.

* **Something for something [quid pro quo]**

* **Identity fraud**

## Social Engineering  Tactics

* **Authority**
  
  When a users is instructed by someone they perceive as an authority figure

* **Intimidation**

* **Consensus / Social proof**
  
  Based on the fact that people tend to act in the same way as other people around them, thinking that something must be right if others are doing it

* **Scarcity**
  
  Based on the fact that people tend to act in a certain way when there is a limited quantity of something available

* **Urgency**

* **Familiarity**
  
  People are more likely to do what another person asks if they like this person

* **Trust**
  
  Building trust in a relationship with a victim may require more time to establish

---

### Shoulder Surfing

It is a simple attack that involves observing or literally looking over a target's shoulder to gain valuable information

### Dumpster Diving

It is the process of going through a target's trash to see what information has been thrown out

### Piggybacking and Tailgating

It occurs when a criminal follows an authorized person to gain physical entry into a secure location

---

### Invoice Scam

Fake invoices are sent with the goal of receiving money from a victim by prompting them to put their credentials into fake login screen

### Watering hole attack

It is an exploit in which an attacker observes or guesses what websites an organization uses most often, and infects one or more of them with malware

### Typosquatting

Incorrect URL can redirect to a legitimate-looking website owned by the attacker

---

# Cyber Attacks

## Viruses

It is a type of computer program that, when executed, replicates and attaches itself to other files, such as legitimate program, by inserting its own code into it.

Once a virus is active, it will usually infect other programs on the computer or other computers on the network.

## Worms

It is a malicious software program that replicates by independently exploiting vulnerabilities in networks. The initial infection of the host, they do not require user participation and can spread very quickly over the network, usually slowing it down.

## Trojan horse

It is a malware that carries out malicious operations by masking its true intent.

## Logic Bombs

It is a malicious program that waits for a trigger, such as a specified date or database entry, to set off the malicious code.

Once activated, a logic bomb implements a malicious code that causes harm to a computer in various ways. It can sabotage database records, erase files and attack operating systems or applications.

They can also attack and destroy hardware components, overdriving components.

## Ramsomware

This malware is designed to hold a computer system or the data it contains captive until a payment is made.

## Denial of Service [DoS] attacks

Those are a type of network attack that is relatively simple to conduct, even for an unskilled attacker. They usually result in some sort of interruption to network services, causing a significant loss of time and money.

* **Overwhelming quantity of traffic**

* **Malicious formatted packets**, the receiver of the packet it's unable to handle it

---

## Domain Name System

These are many essential technical services needed for a network to operate

* **Domain reputation**
  
  **Domain Name System [DNS]** is used by DNS servers to translate a domain name. If a DNS server does not know an IP address, it will ask another DNS server.
  
  An organization needs to monitor its domain reputation, including its IP address, to help protect against malicious external domains

* **DNS spoofing**
