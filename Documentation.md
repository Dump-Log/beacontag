### Problem Definition

1. Specific problem this addresses
- This tool aims to enrich the context of periodic network communications by generating Wireshark tags. Tools for detecting C2 beaconing or periodic heartbeat traffic are not new; however, I wasn't able to find any that incorporated the results into the network pcap. Another problem this approach attempts to address is the time required to set up the environment.  Many popular tools, such as RITA, use ZEEK logs as input, which creates an additional step if only a pcap is available.

2. Why is this problem important
- In both threat hunting and protocol analysis, detecting periodic and repeatable traffic can be important. In threat hunting, it is often indicative of C2 activity related to malicious intent; when analyzing an IoT device, it may highlight the heartbeat interval to the cloud. By having a tool that can identify and tag the traffic
which is then viewable in Wireshark; it means you can use familiar processes while checking whether a packet is part of a periodic check.

3. Existing tools or approaches
- There are plenty of C2 detectors and methods for detecting periodicity; it is a common network metric. However, I was not able to find any existing tools that augment a pcap and provide this type of context enrichment. 

4. What Gap does this tool fill
- It provides contextual information in Wireshark about sessions and whether they exhibit periodicity.

### System Design

1. High-Level Architecture
- Everything runs in Docker. You submit a pcap file, which is analyzed using common methods to detect periodicity.
Once the calculations are complete, an output pcapng file is generated with the results in comments.
You can view that in Wireshark and enable a comments column to view it, or sort as necessary.

2. Technological choices and justification
- Docker was picked because the tool relies on Wireshark, tshark, and various Python libraries; this makes it reproducible with pinned versions
- The periodicity is determined using a weight of:
- Median Absolute Deviation (MAD) - this is similar to Coefficient of Variation(COV) but is more resistant to outliers.
- Lomb-Scargle Algorithm: it is used to detect periodic signals in unevenly spaced time-series data; not all C2's or IoTs are active and transmit at every interval.
- Count: More check-ins, more confidence.
- Size: Consistency of bytes transmitted per check-in session.

### Evaluation

1. How I tested
- I used a previous project to generate some pcaps, introducing different levels of jitter (time variance between beacons).
- Publicly available pcap data from real C2 activity with normal background traffic.
- AI-generated pcaps to test specific scenarios.

2. Results
- Periodicity detection is often full of false positives, and that was no different for this tool. Depending on the behavior of the traffic, sometimes different weights needed to be adjusted for more predictable results.

3. Known Issues
- Things like NTP often exhibit a strong periodicity and will be flagged.
I am not excluding common IP’s used by Google or CDN’s so this may result in many flagged packets. Some future work would be to incorporate IP reputation and add a switch to prevent flagging good reputation IPs.
