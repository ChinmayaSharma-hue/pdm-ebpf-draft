---
title: "Implementation and Performance Evaluation of PDM using eBPF"
abbrev: "pdm-ebpf"
category: info

docname: draft-elkins-ebpf-pdm-ebpf-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - pdm
 - ebpf
 - performance
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "ChinmayaSharma-hue/pdm-ebpf-draft"
  latest: "https://ChinmayaSharma-hue.github.io/pdm-ebpf-draft/draft-elkins-ebpf-pdm-ebpf.html"

author:
  -
    fullname: "Nalini Elkins"
    organization: "Inside Products, Inc."
    email: "nalini.elkins@insidethestack.com"
  -
    fullname: "Chinmaya Sharma"
    organization: "NITK Surathkal"
    email: "chinmaysharma1020@gmail.com"
  -
    fullname: "Amogh Umesh"
    organization: "NITK Surathkal"
    email: "amoghumesh02@gmail.com"
  -
    fullname: "Balajinaidu V"
    organization: "NITK Surathkal"
    email: "balajinaiduhanur@gmail.com"
  -
    fullname: "Mohit P. Tahiliani"
    organization: "NITK Surathkal"
    email: "tahiliani@nitk.edu.in"


normative:
  RFC8250: RFC8250

informative:

--- abstract

RFC8250 describes an optional Destination Option (DO) header embedded in each packet to provide sequence numbers and timing information as a basis for measurements. As kernel implementation can be complex and time-consuming, this document describes the implementation of the Performance and Diagnostic Metrics (PDM) extension header using eBPF in the Linux kernel's Traffic Control (TC) subsystem. The document also provides a performance analysis of the eBPF implementation in comparison to the traditional kernel implementation.


--- middle

# Introduction

## Background

### PDM

The Performance and Diagnostic Metrics (PDM) Extension Header, designated in RFC 8250, introduces a method to discern server processing delays from round trip network delays within IPv6 networks. This extension is a type of Destination Options header, a component of the IPv6 protocol.

The PDM header incorporates several fields, notably Packet Sequence Number This Packet (PSNTP), Packet Sequence Number Last Received (PSNLR), Delta Time Last Received (DTLR), Delta Time Last Sent (DTLS), and scaling factors for these delta times. These elements, when correlated with a unique 5-tuple identifier, facilitate the precise measurement of network and server delays. The PDM header's utility lies in its ability to provide concrete data on network and server performance. By differentiating between the delays caused by network round trips and server processing, it enables quick identification of performance bottlenecks.

Implementations of the PDM header must keep track of sequence numbers and timestamps for both incoming and outgoing packets, associated with each 5-tuple. The header's design emphasizes flexibility in its activation, accuracy in timestamp recording, and configurable parameters for information lifespan and memory allocation as detailed in Section 3.5 of RFC 8250.

### eBPF

eBPF, an extensible programming framework within the Linux kernel, operates as a virtual machine allowing users to run isolated programs in kernel space, thereby customizing network processing, monitoring, and security without needing kernel recompilation. These user-defined programs are first compiled into eBPF bytecode, followed by a verification process that assures termination and checks for potential errors such as invalid pointers or array bounds, adding an extra layer of security. Due to their optimized bytecode, eBPF programs run efficiently within the kernel's virtual machine. eBPF offers various hook points within the kernel, such as in the networking stack, enabling users to attach their programs based on specific requirements, like network monitoring or packet modification. This flexibility allows for a tailored kernel behavior to suit different use cases, enhancing the system's functionality and security.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Using tc-bpf to add IPv6 extension headers

## tc-bpf

The cls_bpf component within tc is a classifier that uses BPF, including both classic BPF (cBPF) and extended BPF (eBPF), for packet filtering and classification. eBPF can be used to directly perform actions on the socket buffer (skb), such as packet mangling or updating checksums. One of the features of cls_bpf classifier is its ability to facilitate efficient, non-linear classification. Unlike traditional tc classifiers that may require multiple parsing passes (one each per classifier), cls_bpf, with the help of eBPF, can tailor a single program for diverse skb types, avoiding redundant parsing.

cls_bpf operates in two distinct modes: originally calling into the full tc action engine, tcf_exts_exec and a more efficient 'direct action' (da) mode for immediate return after bpf run. The da mode allows cls_bpf to simply return a tc opcode and perform tc actions without the need for traversing multiple layers in the tc action engine.

In direct-action(da) mode, eBPF can store class identifiers (classid) in skb->tc_classid and return the action opcode, suitable even for simple cBPF operations like drop actions. cls_bpf's flexibility also allows administrators to use multiple classifiers in mixed modes (da and non-da) based on specific use cases. However, for high-performance workloads, a single tc eBPF cls_bpf classifier in da mode is generally sufficient and recommended due to its efficiency.

## Adding IPv6 extension headers in tc

Adding an extension header to the packet requires creating space for the header followed by inserting the data and padding. This task utilizes eBPF helper functions specific to packet manipulation with skb, such as bpf_skb_adjust_room for creating space, bpf_skb_load_bytes for loading data from skb, and bpf_skb_store_bytes for storing bytes in the adjusted skb.

The tc-bpf hookpoint caters to both ingress and egress traffic, vital in scenarios where measurements in ingress are needed or when packet data in ingress is used for calculating extension headers in egress.

The traffic control subsystem is located in the lower levels of the network stack, which implies minimal packet processing after this stage. Adding an extension header after the packet is fully formed can result in the packet exceeding the Maximum Transmission Unit (MTU), leading to potential packet drops. It's important to check the packet size to ensure it doesn't exceed the MTU with the added extension header. The packet size can be verified against the exceeding MTU of net device (based on ifindex) using the bpf_check_mtu helper function.

tc-bpf programs can also utilize the bpf_redirect helper to redirect packets to the ingress or egress TC hook points of any interface in the host, useful for routing purposes. An additional benefit of using TC or any other eBPF hook point is the simplicity in exporting data received in extension headers for logging and monitoring. This is facilitated through eBPF maps, accessible from both kernel and user space. BPF maps like BPF_MAP_TYPE_PERF_EVENT_ARRAY and BPF_MAP_TYPE_RINGBUF are used for streaming real-time data from the extension headers, providing precise control over poll/epoll notifications to userspace about new data in the buffers.

### Ingress tc-bpf program

A BPF program can be attached to the ingress of the clsact qdisc for a specific network interface. This program executes for every packet received on this interface. The purpose of attaching a BPF program at the ingress is to conduct specific measurements necessary for calculating certain fields in the extension header. Should the need arise to categorize information from incoming packets based on the 5-tuple, a hashmap BPF map can be employed. The ability to access BPF maps across different eBPF programs is beneficial, particularly for utilizing data recorded in the ingress BPF program within the egress BPF program.

It's possible to define actions at ingress based on data from incoming packets in direct action mode. For instance, the ingress BPF program might decide to drop a packet based on its received extension header, returning TC_ACT_SHOT, or to forward the packet by returning TC_ACT_OK. Additional actions in the classifier-action subsystem, like TC_ACT_REDIRECT, are available for use with bpf_redirect and other relevant functions.

### Egress tc-bpf program

A BPF program is attachable to the egress point of the clsact qdisc designated for a specific network interface, functioning for every packet exiting this interface. The role of this egress BPF program includes preparing space for the extension header in the skb, assembling the extension header tailored for the particular outbound packet, and appending the extension header to the packet.

In cases where the extension header is stateless, an egress BPF program alone might be adequate, as no flow-related measurements are required. The data to be integrated into the extension header solely depends on the current outgoing packet. If the extension header fields depend on the data from incoming packets or previously sent packets, utilizing BPF maps becomes necessary to store and subsequently utilize this data for computing specific fields in the extension headers.

The egress BPF program also has access to a similar set of actions. For instance, if a packet is discovered to be malformed, the program has the capacity to drop the packet using TC_ACT_SHOT before it is transmitted. Successful addition of the extension header necessitates the return of TC_ACT_OK, propelling the packet to the subsequent phase in the network stack.

The additional advantage of using TC or any other eBPF hook point is that if the data received in the extension headers were of interest in terms of logging and monitoring, the exporting of this data is made really simple through the use of eBPF maps which are accessible from both kernel space and user space. BPF maps of types BPF_MAP_TYPE_PERF_EVENT_ARRAY and BPF_MAP_TYPE_RINGBUF can be used for streaming of the real time data obtained from the extension headers. They give fine grain control to the eBPF program for poll/epoll notifications to any userspace consumer about new data availability in the buffers.

# Implementation of PDM extension header in tc-bpf

PDM is implemented using both ingress and egress tc-bpf programs. The ingress program's chief responsibility lies in the interpretation of incoming packets adorned with the PDM extension header and recording the reception time of these packets. The egress program assumes the role of appending the extension header, leveraging the ingress timestamp to compute the elapsed time since the last packet was received and sent within the same flow. These timestamps are effectively communicated and preserved between the two programs via a BPF map, specifically of the BPF_MAP_TYPE_HASH variety. The mapping key is constituted by the 5-tuple flow, which includes ipv6 source and destination addresses, TCP/UDP source and destination ports, and the Transport layer protocol. In scenarios involving ICMP packets, the source and destination ports are assigned a value of zero.

## Egress tc-bpf program for PDM

The egress eBPF program should first conduct essential validations on the sizes of the ethernet and IP headers, and ascertain whether the packet in question is IPv6. Should the packet be non-IPv6, it returns with the action TC_ACT_OK and the packet proceeds unaltered.

The program subsequently examines if the packet's next header field indicates the presence of an extension header. In instances where any form of extension header exists, the addition of PDM is withheld. This restraint stems from the complexity involved in integrating an extension header, requiring the parsing of existing ones and accurately positioning the PDM header. The challenge is compounded by the limitation of bpf_skb_adjust_room, which permits augmenting the packet size only subsequent to the fixed-length IPv6 header, thus necessitating a reorganization of the other extension headers within the eBPF program.

The egress eBPF program extracts the IPv6 source and destination addresses, and in cases involving TCP/UDP, it also parses the source and destination ports from the transport layer. This data is used in the formulation of a 5-tuple key utilized for accessing the eBPF Map. The program retrieves timestamps and packet sequence number of the last received packet and last sent packet from the eBPF map.

The extension header fields are then computed using the current timestamp, acquired through bpf_ktime_get_ns. This current timestamp is then stored back in the eBPF map under the packet last sent field, for future reference. The Delta Time Last Received (DTLR) field is calculated by determining the difference between the Time Last Sent and Time Last Received of the latest entry. The Delta Time Last Sent (DTLS) is computed as the difference between the Time Last Received of the latest entry and the Time Last Sent of the preceding entry.

The Packet Sequence Number This Packet (PSNTP) is calculated by incrementing the sequence number of the last sent packet. The Packet Sequence Number Last Received (PSNLR) is taken directly from the map. These methodologies are in accordance with Section 3.2.1 of RFC 8250.

Given that PDM is categorized as a destination options extension header, the next header is set accordingly. The space requirement for storing PDM stands at 12 bytes, with an additional 2 bytes for the destination options header and another 2 bytes for padding. Following the execution of bpf_skb_adjust_room to augment the skb size by 16 bytes, the program employs bpf_skb_store_bytes to store the structured destination options header and the PDM header. Upon successful insertion of the header, the egress BPF program finishes its operation by returning TC_ACT_OK.

## Ingress tc-bpf program for PDM

The ingress eBPF program should first conduct essential validations on the sizes of the ethernet and IP headers, and ascertain whether the packet in question is IPv6. Should the packet be non-IPv6, it returns with the action TC_ACT_OK and the packet proceeds unaltered. It also checks if the packet has a destination options header and if it does, it checks if the header is a PDM header.

The calculation of the fields "Delta Time Last Sent" and "Delta Time Last Received," along with their respective scaling factors, is contingent on the "Time Last Received" field located in the BPF map, pertaining to the relevant 5-tuple. The ingress BPF program is responsible for capturing the timestamp when a packet, corresponding to a specific 5-tuple, is received. This capture is executed using the function bpf_ktime_get_ns, and the result is subsequently stored in the map.

In the context of outgoing packets during egress, the "Packet Sequence Number Last Received" is derived from the "Packet Sequence Number This Packet" field located in the PDM header of the received packet. After the successful storage of both these values in the BPF map, the ingress BPF program finishes its operation by returning TC_ACT_OK.

## Implementation of PDM initiation

The process of adding Performance and Diagnostic Metrics (PDM) involves verifying the existence of an entry for the corresponding 5-tuple within the BPF map. If no such entry exists, the program initiates PDM for this flow by creating a new one..This action is prompted each time an IPv6 packet is either received or transmitted.

The structure of the entries in the BPF map consists of the 5-tuple serving as the key and the value encompassing various elements such as the Packet Sequence Number Last Sent (PSNLS), Packet Sequence Number Last Received (PSNLR), Time Last Received (TLR), and Time Last Sent (TLS).

During the initial phase, the Packet Sequence Number Last Sent (PSNLS) is assigned a random value, achieved through the use of the helper function bpf_get_prandom_u32, which generates a random 32-bit integer. Additionally, for the first packet, the Packet Sequence Number Last Received (PSNLR) and Time Last Received (TLR) are set to zero, as the ingress BPF program has not yet been executed for the specific 5-tuple.

## Implementation of PDM termination

Stale entries corresponding to a flow are to be removed after a certain amount of time, as new flows with the same 5-tuple can use the stale data stored for the same 5-tuple a long time ago. This should be done through a configurable maximum lifetime limit for the entries.

One way to remove stale entries is through constant polling of the map to check for entries that have not been updated for the configured period, which identifies the entries as stale entries. This can be done using userspace programs as BPF maps are accessible from both the kernel space and user space. All the entries in the map are checked, and stale entries are removed using the bpf_map_delete_elem helper function.

Another way is to handle this mechanism completely in eBPF by calculating the differences between Time Last Sent (TLS) and Time Last Received (TLR) with the current timestamp for every single packet in both ingress and egress and if both these differences are above a configured maximum limit, then the map entry fields are reset and the PDM flow for that 5 tuple is reinitialized.

# Advantages of using eBPF to add extension headers

eBPF offers the capability for dynamic loading and unloading of BPF programs, facilitating the ease of activating or deactivating the insertion of extension headers into outgoing packets. The utilization of tc and xdp hook points enhances the precision of timestamps for wire arrival time, due to their location at the lower layers of the network stack. Additionally, eBPF simplifies memory management in high traffic scenarios, as it allows for the configuration of the maximum number of entries in eBPF maps via its API.

eBPF programs are also very portable and can be used across different kernel versions as long as it is compatible. This is beneficial as it allows for the easy migration of the PDM implementation across different kernel versions, ensuring that the PDM implementation remains consistent across different kernel versions.

Implementing extension header insertion within the kernel can introduce development challenges, such as potential memory leaks due to inadequate memory deallocation processes. The configurability of the maximum number of entries in a BPF map addresses this issue, preventing memory overflow. The presence of the BPF verifier is instrumental in ensuring both security and simplicity of implementation. It conducts essential checks, including pointer validation, buffer overflow prevention, and loop avoidance in the code, thereby mitigating the risks of crashes or security vulnerabilities. To safeguard against misuse, eBPF imposes resource constraints on programs, such as limits on the number of executable instructions, thereby upholding system stability and integrity.

# Performance Analysis

## Experiment Setup

Two Virtual Machines with 8 cores, 16 GB of Ram and 64 GB of disk space were used to run the following tests. The Virtual Machines are running Ubuntu 22.04 server operating system running linux kernel of version 5.15.148 which was compiled using the same kernel configuration as the prepackaged kernel 5.15.94. Both the VMs are running on the same physical server using Qemu/KVM as hypervisor. We compared the performance of the eBPF implementation of PDM with a traditional kernel implementation of PDM (add reference). The performance metrics used for comparison are CPU Performance, Memory Usage, Network Throughput and Packet Processing Latency.

## CPU Performance

Profiling of CPU cycles consumed by eBPF programs and the kernel implementation has been performed to evaluate the computational overhead introduced by these functions. The perf tool was used to capture CPU cycle events and configured with a polling frequency of 10,000 Hz.

Each experiment was structured to run an iperf3 server session using TCP for a duration of 600 seconds or five minutes, simulating a consistent and controlled traffic load. Iperf was also configured to use an MSS value of 1000 bytes across all tests while the MTU of the interface and path was 1500 bytes. This allowed us to avoid accounting for packet size becoming greater than the MTU in the eBPF program.

This procedure was replicated across fifty individual trials per implementation. The repetition of these trials under uniform conditions and for a long duration allowed for the collection of a comprehensive profile of CPU cycle usage, which is useful for evaluating the efficiency and scalability of the eBPF processing in real-world networking scenarios.

For the eBPF program, perf is able to record data for egress and ingress programs separately. For the
kernel implementation, the pdm_insert function call duration was measured for each iperf3 server session. This represents the overhead in egress in the kernel implementation.

### CPU Usage in cycles

| CPU Usage(cycles)| Mean          | Median        | St. Dev.     |
|------------------|---------------|---------------|--------------|
| eBPF Egress      | 8.60e10 cyc.  | 8.54e10 cyc.  | 9.08e9 cyc.  |
| eBPF Ingress     | 1.53e10 cyc.  | 1.57e10 cyc.  | 8.71e9 cyc.  |
| PDM Kernel Egress| 2.29e9 cyc.   | 2.13e9 cyc.   | 6.49e8 cyc.  |

### CPU usage as a percentage of total CPU cycles

| CPU Usage(%)     | Mean          | Median        | St. Dev.     |
|------------------|---------------|---------------|--------------|
| eBPF Egress      | 0.41%         | 0.40%         | 0.10%        |
| eBPF Egress      | 0.07%         | 0.07%         | 0.03%        |
| PDM Kernel Egress| 0.0110%       | 0.0100%       | 0.0030%      |

The CPU cycles consumed by the PDM Kernel Implementation is lower than the eBPF counterpart. This denotes a measurably higher computational demand for eBPF operations. However, it's noteworthy that the kernel approach, despite its limited flexibility compared to eBPF, demonstrates a lower overhead, signifying its streamlined efficiency.

On a test run with call stack enabled in perf, the percentage overheads of some of the symbols invoked by
eBPF egress function were obtained. The major portion of egress overhead is bpf map read/write operations, and memcpy operation for the copy of packet data to and from kernel memory.

It would be interesting to examine the effect of lowering the number of bpf_skb_store_bytes and bpf_skb_load_bytes by loading the entire packet into the eBPF program, modifying the packet in the eBPF program and then storing the modified packet into skb. The current implementation invokes bpf_skb_store_bytes and bpf_skb_load_bytes many times for disjoint parts of the packet. This could be a potential optimization for the eBPF program.

## Memory Usage

This PDM implementation using eBPF uses memory while storing the state of the 5 tuple flows. The memory management is handled by eBPF maps. Each map entry stores a value of size 20 bytes - 2 bytes each for Packet Sequence Number This Packet (PSNTP) and Packet Sequence Number Last Received (PSNLR) and 8 bytes each for Time Last Sent (TLS) and Time Last Received (TLR).

The BPF maps have been configured to a maximum limit of 65,536 entries. This means the implementation can handle 65,536 flows at once. While handling the maximum of these flows we will expect the total data to be stored in the eBPF maps to be 1310720 Bytes or 1.3 MB. There is additional overhead added by the eBPF maps structures themselves but the effect on this total is not very large.

If more than 65,536 flows are encountered then new flows replace older entries in the maps. The BPF_MAP_TYPE_LRU_HASH variant of the BPF Hash Map is used in the implementation so the older flows are replaced in a least recently used fashion.

## Network Throughput


| Network Throughput           | Mean        | Median      | St. Dev.   |
|------------------------------|-------------|-------------|------------|
| Without PDM                  | 18.80 Gbps  | 18.58 Gbps  | 2.19 Gbps  |
| PDM Kernel Implementation    | 18.52 Gbps  | 18.33 Gbps  | 2.21 Gbps  |
| eBPF Implementation          | 18.03 Gbps  | 17.22 Gbps  | 2.51 Gbps  |

Profiling of Network Throughput consumed by attaching PDM extension header has been done to determine the throughput overhead. Each experiment was structured to run an iperf3 server session using TCP for a duration of 600 seconds or five minutes, simulating a consistent and controlled traffic load. There was no perf running in any of these tests.

This procedure was replicated across twenty five individual trials. The repetition of these trials were conducted under uniform conditions. The network throughput was measured for the case when PDM is not attached, when PDM is attached using the kernel implementation and when PDM is attached using the eBPF implementation.

When PDM is not attached, the network throughput is the highest as expected. A slight decrease is observed in the kernel implementation, with a further decrease in the eBPF implementation. This indicates that while both methods impact network performance, the eBPF implementation has a slightly more pronounced effect. The standard deviation across these measurements suggests some variability in the test network conditions. This might be a result to consider while implementing extension headers in eBPF.

| TCP Retransmits              | Mean        | Median      | St. Dev.   |
|------------------------------|-------------|-------------|------------|
| Without PDM                  | 2.125       | 2.0         | 1.832      |
| PDM Kernel Implementation    | 44.125      | 41.5        | 13.531     |
| eBPF Implementation          | 37.565      | 36.0        | 10.133     |

The TCP retransmits were extracted for the test runs conducted for network throughput. The number of TCP retransmits is higher when PDM is attached using the kernel implementation and the eBPF implementation. This might be due to a fault in the implementation itself or packet drops happening due to extension header addition.

## Packet Processing Latency

| Packet Processing Latency               | Mean      | Median    | St. Dev.  |
|-----------------------------------------|-----------|-----------|-----------|
| PDM Kernel Implementation               | 0.707 µs  | 0.641 µs  | 0.414 µs  |
| eBPF Egress Program Attached            | 5.808 µs  | 6.142 µs  | 0.986 µs  |
| eBPF Egress Program Detached            | 4.528 µs  | 4.668 µs  | 0.785 µs  |
| eBPF Ingress Program Attached           | 3.634 µs  | 3.977 µs  | 0.906 µs  |
| eBPF Ingress Program Detached           | 3.082 µs  | 3.321 µs  | 1.246 µs  |

Functions within the kernel involved in packet processing can be profiled using ftrace to determine the exact duration taken in processing packets. The PDM insertion function (which is a part of the PDM Kernel Implementation) call duration was measured for a duration of 15 minutes while running an iperf3 server session.

For egress eBPF program, the duration of dev_queue_xmit() function call in the kernel was measured with and without the eBPF egress program attached for a duration of 15 minutes while running an iperf3 server session. Similarly, for the ingress eBPF program, the duration of netif_receive_skb_list_internal() function call in the kernel was measured with and without the eBPF ingress program attached for a duration of 15 minutes while running an iperf3 server session.

The profiling of eBPF egress program with respect to packet processing latency is done by calculating the difference in the duration of dev_queue_xmit() function call in the kernel with and without the eBPF egress program attached. This indicates that the eBPF egress program introduces a latency of approximately 1.280 µs.

The profiling of eBPF ingress program with respect to packet processing latency is done by calculating the difference in the duration of netif_receive_skb_list_internal() function call in the kernel with and without the eBPF ingress program attached. This indicates that the eBPF ingress program introduces a latency of approximately 0.552 µs.
It should be noted however that ftrace is affected by context switches and scheduling latencies in the kernel and the scheduling of the VM itself on the host.

# Security Considerations

BPF utilizes maps to store various data elements, including 5-tuple information about network flows. These maps have a configurable limit on the number of entries they can hold, which is crucial for efficient memory usage and performance optimization. However, this characteristic also opens up a potential vulnerability to resource exhaustion attacks.

An attacker, by intentionally sending packets with numerous distinct 5-tuples, could overrun the BPF maps. As these maps reach their maximum capacity, legitimate new entries cannot be added, or lead to existing entries being replaced by the new flows, potentially leading to incorrect packet processing or denial of service as critical flows might be untracked or misclassified. This scenario is particularly concerning in high-throughput environments where the rate of new flow creation is significant.

To mitigate such attacks, it is essential to implement a robust mechanism that not only monitors the usage of BPF maps but also employs intelligent strategies to handle map overruns. This could include techniques like early eviction of least-recently-used entries, dynamic resizing of maps based on traffic patterns, or even alert mechanisms for anomalous growth in map entries.

Additionally, rate-limiting strategies could be enforced at the network edge to prevent an overwhelming number of new flows from entering the network, thus offering a first line of defense against such resource exhaustion attacks.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

The Authors extend their gratitude to Ameya Deshpande for providing the kernel implementation of PDM, which served as a  basis for comparison with the eBPF implementation.
