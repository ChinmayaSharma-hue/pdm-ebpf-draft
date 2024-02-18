---
title: "Performance Evaluation of PDM Implementation using eBPF in TC versus Traditional Kernel Methods"
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
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "ChinmayaSharma-hue/pdm-ebpf-draft"
  latest: "https://ChinmayaSharma-hue.github.io/pdm-ebpf-draft/draft-elkins-ebpf-pdm-ebpf.html"

author:
 -
    fullname: "Chinmay"
    organization: NITK Surathkal
    email: "chinmaysharma1020@gmail.com"

normative:

informative:


--- abstract

RFC8250 describes an optional Destination Option (DO) header embedded in each packet to provide sequence numbers and timing information as a basis for measurements. As kernel implementation can be complex and time-consuming, this document describes the implementation of the Performance and Diagnostic Metrics (PDM) extension header using eBPF in the Linux kernel's Traffic Control (TC) subsystem. The document also provides a performance analysis of the eBPF implementation in comparison to the traditional kernel implementation.


--- middle

# Introduction

## Background

### PDM

The Performance and Diagnostic Metrics (PDM) Extension Header, designated in RFC 8250, introduces a method to discern server processing delays from round trip network delays within IPv6 networks. This extension is a type of Destination Options header, a component of the IPv6 protocol.

The PDM header incorporates several fields, notably Packet Sequence Number This Packet (PSNTP), Packet Sequence Number Last Received (PSNLR), Delta Time Last Received (DTLR), Delta Time Last Sent (DTLS), and scaling factors for these delta times. These elements, when correlated with a unique 5-tuple identifier, facilitate the precise measurement of network and server delays. The PDM header's utility lies in its ability to provide concrete data on network and server performance. By differentiating between the delays caused by network round trips and server processing, it enables quick identification of performance bottlenecks. This distinction is vital for efficient network management and troubleshooting.

Implementations of the PDM header must keep track of sequence numbers and timestamps for both incoming and outgoing packets, associated with each 5-tuple. The header's design emphasizes flexibility in its activation, accuracy in timestamp recording, and configurable parameters for information lifespan and memory allocation as detailed in Section 3.5 of RFC 8250.

### eBPF

eBPF, an extensible programming framework within the Linux kernel, operates as a virtual machine allowing users to run isolated programs in kernel space, thereby customizing network processing, monitoring, and security without needing kernel recompilation. These user-defined programs are first compiled into eBPF bytecode, followed by a verification process that checks for potential errors such as invalid pointers or array bounds, adding an extra layer of security. Due to their optimized bytecode, eBPF programs run efficiently within the kernel's virtual machine. eBPF offers various hook points within the kernel, such as in the networking stack, enabling users to attach their programs based on specific requirements, like network monitoring or packet modification. This flexibility allows for a tailored kernel behavior to suit different use cases, enhancing the system's functionality and security.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Using tc-bpf to add IPv6 extension headers

## tc-bpf

The cls_bpf component within tc is a classifier that uses BPF, including both classic BPF (cBPF) and extended BPF (eBPF), for packet filtering and classification. It operates in two distinct modes: the original mode, which uses tcf_exts_exec() for executing actions after classification, and a more efficient 'direct action' (da) mode. The da mode, optimized for eBPF, allows cls_bpf to directly perform actions on the socket buffer (skb), such as packet mangling or updating checksums, without the need for traversing multiple layers in the tc action engine. This results in a streamlined process where cls_bpf simply returns a tc opcode, facilitating a compact and efficient skb processing path.
In direct-action(da) mode, eBPF can store class identifiers (classid) in skb->tc_classid and return the action opcode, suitable even for simple cBPF operations like drop actions. cls_bpf's flexibility also allows administrators to use multiple classifiers in mixed modes (da and non-da) based on specific use cases. However, for high-performance workloads, a single tc eBPF cls_bpf classifier in da mode is generally sufficient and recommended due to its efficiency.
One of the features of cls_bpf is its ability to facilitate efficient, non-linear classification. Unlike traditional tc classifiers that may require multiple parsing passes, cls_bpf, with the help of eBPF, can tailor a single program for diverse skb types, avoiding redundant parsing. This efficiency is further optimized through eBPF tail call program constructs, enabling atomic packet parser replacements based on classification outcomes.

## Adding IPv6 extension headers in tc
The traffic control subsystem is located in the lower levels of the network stack. This indicates that the packet is almost fully processed, and thus, adding an extension header at this juncture requires creating space for the header followed by inserting the data and padding. This task utilizes eBPF helper functions specific to packet manipulation with skb, such as bpf_skb_adjust_room for creating space, bpf_skb_load_bytes for loading data from skb, and bpf_skb_store_bytes for storing bytes in the adjusted skb.

The tc bpf hookpoint caters to both ingress and egress traffic, vital in scenarios where measurements in ingress are needed or when packet data in ingress is used for calculating extension headers in egress. Adding an extension header after the packet is fully formed can result in the packet exceeding the Maximum Transmission Unit (MTU), leading to potential packet drops. It's important to check the packet size to ensure it doesn't exceed the MTU with the added extension header.

TC-BPF programs can also utilize the bpf_redirect helper to redirect packets to the ingress or egress TC hook points of any interface in the host, useful for routing purposes. An additional benefit of using TC or any other eBPF hook point is the simplicity in exporting data received in extension headers for logging and monitoring. This is facilitated through eBPF maps, accessible from both kernel and user space. BPF maps like BPF_MAP_TYPE_PERF_EVENT_ARRAY and BPF_MAP_TYPE_RINGBUF are used for streaming real-time data from the extension headers, providing precise control over poll/epoll notifications to userspace about new data in the buffers.

### Ingress tc-bpf program

A BPF program can be attached to the ingress of the clsact qdisc for a specific network interface. This program executes for every packet received on this interface. The purpose of attaching a BPF program at the ingress is to conduct specific measurements necessary for calculating certain fields in the extension header. Should the need arise to categorize information from incoming packets based on the 5-tuple, a hashmap BPF map can be employed. The ability to access BPF maps across different eBPF programs is beneficial, particularly for utilizing data recorded in the ingress BPF program within the egress BPF program.

It's feasible to define actions at ingress based on data from incoming packets. This capability stems from the traffic control classifier-action subsystem, which examines incoming packet data and/or metadata, employing a combination of classifier filters and action executions to fulfill a specified policy. For instance, the ingress BPF program might decide to drop a packet based on its received extension header, returning TC_ACT_SHOT, or to forward the packet by returning TC_ACT_OK. Additional actions in the classifier-action subsystem, like TC_ACT_REDIRECT, are available for use with bpf_redirect and other relevant functions.

### Egress tc-bpf program

A BPF program is attachable to the egress point of the clsact qdisc designated for a specific network interface, functioning for every packet exiting this interface. The role of this egress BPF program encompasses preparing space for the extension header in the skb, assembling the extension header tailored for the particular outbound packet, and appending the extension header to the packet. In cases where the extension header is stateless, an egress BPF program alone is adequate, as no flow-related measurements are required. The data to be integrated into the extension header solely depends on the current outgoing packet. Conversely, if the extension header fields are influenced by data from incoming packets or previously sent packets, utilizing BPF maps becomes necessary to store and subsequently utilize this data for computing specific fields in the extension headers.

The egress BPF program also has access to a similar set of actions. For instance, if a packet is discovered to be malformed, the program has the capacity to drop the packet using TC_ACT_SHOT before it is transmitted. Conversely, successful addition of the extension header necessitates the return of TC_ACT_OK, propelling the packet to the subsequent phase in the network stack.

The additional advantage of using TC or any other eBPF hook point is that if the data received in the extension headers were of interest in terms of logging and monitoring, the exporting of this data is made really simple through the use of eBPF maps which are accessible from both kernel space and user space. BPF maps of types BPF_MAP_TYPE_PERF_EVENT_ARRAY and BPF_MAP_TYPE_RINGBUF can be used for streaming of the real time data obtained from the extension headers. They give fine grain control to the eBPF program for poll/epoll notifications to any userspace consumer about new data availability in the buffers.

# Implementation of PDM extension header in tc-bpf

PDM is implemented using both ingress and egress TC-BPF programs. The ingress program's chief responsibility lies in the interpretation of incoming packets adorned with the PDM extension header and recording the reception time of these packets. Conversely, the egress program assumes the role of appending the extension header, leveraging the ingress timestamp to compute the elapsed time since the last packet was received and sent within the same flow. These timestamps are effectively communicated and preserved between the two programs via a BPF map, specifically of the BPF_MAP_TYPE_HASH variety. The mapping key is constituted by the 5-tuple flow, which includes ipv6 source and destination addresses, TCP/UDP source and destination ports, and the Transport layer protocol. In scenarios involving ICMP packets, the source and destination ports are assigned a value of zero.

## Egress TC-BPF program for PDM

The egress eBPF program initiates its process by conducting essential validations on the sizes of the ethernet and IP headers, and ascertains whether the packet in question is IPv6. Should the packet be non-IPv6, it proceeds unaltered. The program subsequently examines if the packet's next header field indicates the presence of an extension header. In instances where any form of extension header exists, the addition of PDM is withheld. This restraint stems from the complexity involved in integrating an extension header, requiring the parsing of existing ones and accurately positioning the PDM. The challenge is compounded by the limitation of bpf_skb_adjust_room, which permits augmenting the packet size only subsequent to the fixed-length IPv6 header, thus necessitating a reorganization of the other extension headers within the eBPF program.

Furthermore, the egress eBPF program extracts the IPv6 source and destination addresses, and in cases involving TCP/UDP, it also parses the source and destination ports from the transport layer. This data culminates in the formulation of a 5-tuple key utilized for accessing the eBPF Map. The program retrieves timestamps marking the receipt and dispatch of the last packet and the packet sequence number of last packet sent and last packet received from the eBPF map. The extension header fields are then computed using the current timestamp, acquired through bpf_ktime_get_ns. This current timestamp is then stored back in the eBPF map under the packet last sent field, for future reference. The Delta Time Last Received (DTLR) field is calculated by determining the difference between the Time Last Sent and Time Last Received of the latest entry. The Delta Time Last Sent (DTLS) is computed as the difference between the Time Last Received of the latest entry and the Time Last Sent of the preceding entry. The Packet Sequence Number This Packet (PSNTP) is calculated by incrementing the sequence number of the last sent packet. The Packet Sequence Number Last Received (PSNLR) is taken directly from the map. This methodology is in accordance with Section 3.2.1 of RFC 8250.

Given that PDM is categorized as a destination options extension header, the next header is set accordingly. The space requirement for storing PDM stands at 14 bytes, with an additional 2 bytes for the destination options header. Following the execution of bpf_skb_adjust_room to augment the skb size by 16 bytes, the program employs bpf_skb_store_bytes to record the structured destination options header and the PDM header. Upon successful insertion of the header, the egress BPF program concludes its operation by returning TC_ACT_OK.

## Ingress TC-BPF program for PDM

The calculation of the fields "Delta Time Last Sent" and "Delta Time Last Received," along with their respective scaling factors, is contingent on the "Time Last Received" field located in the BPF map, pertaining to the relevant 5-tuple. The ingress BPF program is responsible for capturing the timestamp when a packet, corresponding to a specific 5-tuple, is received. This capture is executed using the function bpf_ktime_get_ns, and the result is subsequently stored in the map. In the context of outgoing packets during egress, the "Packet Sequence Number Last Received" is derived from the "Packet Sequence Number This Packet" field located in the PDM header of the received packet. After the successful storage of both these values in the BPF map, the ingress BPF program concludes its operation by returning TC_ACT_OK.

## Implementation of PDM initiation

The process of initiating Performance and Diagnostic Metrics (PDM) in the context of IPv6 involves verifying the existence of an entry for the corresponding 5-tuple within the BPF map. If no such entry exists, the protocol necessitates the creation of a new one. This action is prompted each time an IPv6 packet is either received or transmitted. The structure of the entries in the BPF map consists of the 5-tuple serving as the key and the value encompassing various elements such as the Packet Sequence Number Last Sent (PSNLS), Packet Sequence Number Last Received (PSNLR), Time Last Received (TLR), and Time Last Sent (TLS). During the initial phase, the Packet Sequence Number Last Sent (PSNLS) is assigned a random value, achieved through the use of the helper function bpf_get_prandom_u32, which generates a random 32-bit integer. Additionally, for the first packet, the Packet Sequence Number Last Received (PSNLR) and Time Last Received (TLR) are set to zero, as the ingress BPF program has not yet been executed for the specific 5-tuple.

## Implementation of PDM termination

Stale entries corresponding to a flow are to be removed after a certain amount of time, as new flows with the same 5-tuple can use the data stored for the same 5-tuple a long time ago. This should be done through a configurable maximum lifetime limit for the entries.

One way to remove stale entries is through constant polling of the map to check for entries that have not been updated for the configured period, which identifies the entries as stale entries. This can be done using userspace programs as BPF maps are accessible from both the kernel space and user space. All the entries in the map are checked, and stale entries are removed using the bpf_map_delete_elem helper function.

Another way is to handle this mechanism completely in eBPF by calculating the differences between Time Last Sent (TLS) and Time Last Received (TLR) with the current timestamp in both ingress and egress and if both these differences are above a configured maximum limit, then the map entry fields are reset and the PDM flow for that 5 tuple is reinitialized.

# Advantages of using eBPF to add extension headers

eBPF offers the capability for dynamic loading and unloading of BPF programs, facilitating the ease of activating or deactivating the insertion of extension headers into outgoing packets. The utilization of tc and xdp hook points enhances the precision of timestamps for wire arrival time, due to their location at the lower layers of the network stack. Additionally, eBPF simplifies memory management in high traffic scenarios, as it allows for the configuration of the maximum number of entries in eBPF maps via its API. This feature extends to setting the maximum lifetime for these entries, enabling their systematic removal through userspace access to eBPF maps.

In contrast, implementing extension header insertion within the kernel can introduce challenges, such as potential memory leaks due to inadequate memory deallocation processes. The configurability of the maximum number of entries in a BPF map addresses this issue, preventing memory overflow. The presence of the BPF verifier is instrumental in ensuring both security and simplicity of implementation. It conducts essential checks, including pointer validation, buffer overflow prevention, and loop avoidance in the code, thereby mitigating the risks of crashes or security vulnerabilities. To safeguard against misuse, eBPF imposes resource constraints on programs, such as limits on the number of executable instructions, thereby upholding system stability and integrity.

# Performance Analysis

## Experiment Setup

Two Virtual Machines with 8 cores, 16 GB of Ram and 64 GB of disk space were used to run the following tests. The Virtual Machines are running Ubuntu 22.04 server operating system running linux kernel of version 5.15.148 which was compiled using the same kernel configuration as the prepackaged kernel 5.15.94. Both the VMs are running on the same physical server using Qemu/KVM as hypervisor.

## Performance Metrics

+--------------------------------+------------+------------+-----------+<br>
|
&nbsp;CPU Usage&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|&nbsp;
Mean&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
Median&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
St. Dev.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|<br>
+--------------------------------+-------------------------------------+<br>
|&nbsp;eBPF Egress CPU cycles&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
8.60e10&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|&nbsp;8.54e10&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
9.08e9&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|<br>
|&nbsp;eBPF Ingress CPU cycles&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
1.53e10&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
1.57e10&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
8.71e9&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|<br>
|&nbsp;
PDM Kernel CPU cycles&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|
&nbsp;2.29e9&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
2.13e9&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
6.49e8&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|<br>
+--------------------------------+------------+------------+-----------+<br>
|&nbsp;
Network Throughput (Gbps)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;Mean&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;Median&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;St. Dev.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|<br>
+--------------------------------+-------------------------------------+<br>
|&nbsp;Without PDM&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
18.80 Gbps&nbsp;
|&nbsp;
18.58 Gbps&nbsp;
|&nbsp;
2.19 Gbps&nbsp;&nbsp;
|<br>
|&nbsp;
PDM Kernel Implementation&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
18.52 Gbps&nbsp;
|&nbsp;
18.33 Gbps&nbsp;
|&nbsp;
2.21 Gbps&nbsp;&nbsp;
|<br>
|&nbsp;
eBPF Implementation&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
18.03 Gbps&nbsp;
|&nbsp;
17.22 Gbps&nbsp;&nbsp;
|&nbsp;
2.51 Gbps&nbsp;&nbsp;
|<br>
+--------------------------------+------------+------------+-----------+<br>
|&nbsp;
Packet Processing Latency (µs)&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
Mean&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
Median&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
St. Dev.&nbsp;&nbsp;&nbsp;&nbsp;
|<br>
+--------------------------------+------------+------------+-----------+<br>
|&nbsp;
PDM Kernel Implementation&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
0.642 µs&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
0.640 µs&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
0.268 µs&nbsp;&nbsp;&nbsp;
|<br>
|&nbsp;
eBPF Egress Program Attached&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
6.117 µs&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
6.263 µs&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
0.769 µs&nbsp;&nbsp;&nbsp;
|<br>
|&nbsp;
eBPF Egress Program Detached&nbsp;&nbsp;&nbsp;
|&nbsp;
4.899 µs&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
4.938 µs&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
0.779 µs&nbsp;&nbsp;&nbsp;&nbsp;
|<br>
|&nbsp;
eBPF Ingress Program Attached&nbsp;&nbsp;&nbsp;
|&nbsp;
5.790 µs&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
4.550 µs&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
3.156 µs&nbsp;&nbsp;&nbsp;&nbsp;
|<br>
|&nbsp;
eBPF Ingress Program Detached&nbsp;&nbsp;
|&nbsp;
3.060 µs&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
3.310 µs&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
|&nbsp;
0.949 µs&nbsp;&nbsp;&nbsp;
|<br>
+----------------------------------------------------------------------+<br>

## CPU Performance

Profiling of CPU cycles consumed by eBPF programs and the kernel implementation has been performed to evaluate the computational overhead introduced by these functions. The perf tool configured to sample CPU cycles at a fine-grained polling frequency of 10,000 Hz was used to capture CPU cycle events. Each experiment was structured to run an iperf3 server session for a duration of five minutes, simulating a consistent and controlled traffic load. This procedure was replicated across fifty individual trials to amass a robust data set. The repetition of these trials under uniform conditions allowed for the collection of a comprehensive profile of CPU cycle usage, which is critical for evaluating the efficiency and scalability of the eBPF processing within real-world networking scenarios.

The egress function, which is responsible for inserting a constructed extension header into each packet, shows a mean CPU cycle count of approximately 8.6e10 CPU cycles, with a standard deviation of 9.07e9 CPU cycles, indicating a moderate dispersion around the mean. In contrast, the ingress function, tasked with timestamping and reading a field from incoming packets, has a significantly lower mean cycle count of around 1.5e10 CPU cycles and a higher relative variability, as reflected by its standard deviation of 8.71e9. The observed range for egress functions is about 4.24e10 cycles, which is substantially higher compared to the ingress function's range of 2.94e9 cycles. This suggests that egress processing is consistently more CPU-intensive than ingress operations, likely due to the additional complexity of header insertion.

Egress overheads tend to converge around a mean of 0.41% of the total number of CPU cycles taken by iperf, displaying a relatively consistent consumption of CPU resources. Ingress overheads, maintaining a lower mean of 0.07%, suggest a minimal impact on CPU usage. Despite the lower averages, variations in overheads were observed, implying discrepancies in CPU loads across multiple executions. Such variability necessitates careful consideration in system design to ensure reliability and efficiency, especially under conditions of high network throughput. The correlation between the volume of data processed and the CPU cycles expended emphasizes the need for meticulous optimization of eBPF programs to prevent performance bottlenecks in traffic-dense environments.

In the kernel implementation of the IPv6 Performance and Diagnostic Metrics (PDM), the construction and insertion of the extension header into the socket buffer (skb) is a sequential process where the pdm_insert function initiates the call to pdm_destopts_insert, which subsequently calls pdm_genopt to assemble the extension header. Profiling of the pdm_insert function revealed a mean CPU cycle overhead of approximately 2.28e9 CPU cycles, with a standard deviation of  6.49e8 CPU cycles indicative of the overhead variability in response to network traffic fluctuations. This function encapsulates the entire process of PDM header insertion and is reflective of the total overhead imparted to the kernel during this operation.

eBPF programs demonstrate a considerable variance in computational intensity, with the egress function's overhead being markedly high at  8.60e10 CPU cycles. This is significantly greater than the mean overhead for the kernel's PDM insertion implementation, which stands at 2.29e9 for pdm_insert. The disparity indicates that while eBPF programs are powerful for network traffic manipulation and control, they also impose a non-trivial computational burden, especially for egress processing here. In contrast, the kernel's PDM processing, although not trivial, consumes less CPU cycles on average, highlighting the importance of optimizing both eBPF and kernel functions to balance functionality with system resource utilization.

## Memory Usage

This PDM implementation using eBPF uses memory while storing the state of the 5 tuple flows. The memory management is handled by eBPF maps. Each map entry stores a value of size 20 bytes - 2 bytes each for Packet Sequence Number This Packet (PSNTP) and Packet Sequence Number Last Received (PSNLR) and 8 bytes each for Time Last Sent (TLS) and Time Last Received (TLR). The BPF maps have been configured to a maximum limit of 65,536 entries. This means the implementation can handle 65,536 flows at once. While handling the maximum of these flows we will expect the total data to be stored in the eBPF maps to be 1310720 Bytes. There is additional overhead added by the eBPF maps structures themselves but the effect on the total is minimal. If more than 65,536 flows are encountered then new flows replace older entries in the maps. The BPF_MAP_TYPE_LRU_HASH variant of the BPF Hash Map is used in the implementation so the older flows are replaced in a least recently used fashion.

## Network Throughput

Profiling of Network Throughput consumed by attaching PDM extension header has been done to determine the throughput overhead. Each experiment was structured to run an iperf3 server session for a duration of five minutes, simulating a consistent and controlled traffic load. This procedure was replicated across fifty individual trials. The repetition of these trials were conducted under uniform conditions. The network throughput was measured for the case when PDM is not attached, when PDM is attached using the kernel implementation and when PDM is attached using the eBPF implementation.

When PDM is not attached, the network throughput averages around 18.80 Gbps. However, with the kernel implementation of PDM, a slight decrease is observed, averaging at 18.52 Gbps. The eBPF implementation further reduces the throughput to an average of 18.03 Gbps. This indicates that while both methods impact network performance, the eBPF implementation has a more pronounced effect. The standard deviation across these measurements suggests variability in network conditions or implementation efficiency. These findings highlight the importance of considering network throughput implications when implementing PDM using different methods, especially in high-throughput environments.

## Packet Processing Latency

Functions within the kernel involved in packet processing can be profiled using ftrace to determine the exact duration taken in processing packets. The PDM insertion function (which is a part of the PDM Kernel Implementation) call duration was measured for a duration of 5 minutes while running an iperf3 server session. For egress eBPF program, the duration of dev_queue_xmit() function call in the kernel was measured with and without the eBPF egress program attached for a duration of 5 minutes while running an iperf3 server session. Similarly, for the ingress eBPF program, the duration of netif_receive_skb_list_internal() function call in the kernel was measured with and without the eBPF ingress program attached for a duration of 5 minutes while running an iperf3 server session..

The PDM insertion function call duration, measured in microseconds, exhibits a mean of approximately 0.642, with a standard deviation indicating a tight clustering of results around this mean. This level of precision in time measurement reflects the efficiency of the kernel's processing capabilities.

The profiling of eBPF egress program with respect to packet processing latency is done by calculating the difference in the duration of dev_queue_xmit() function call in the kernel with and without the eBPF egress program attached. The mean duration of the function call with the eBPF egress program attached is approximately 6.117 µs, with a standard deviation of 0.769 µs. The mean duration of the function call with the eBPF egress program detached is approximately 4.899 µs, with a standard deviation of 0.779 µs. This indicates that the eBPF egress program introduces a latency of approximately 1.218 µs.

The profiling of eBPF ingress program with respect to packet processing latency is done by calculating the difference in the duration of netif_receive_skb_list_internal() function call in the kernel with and without the eBPF ingress program attached. The mean duration of the function call with the eBPF ingress program attached is approximately 5.790 µs, with a standard deviation of 3.156 µs. The mean duration of the function call with the eBPF ingress program detached is approximately 3.060 µs, with a standard deviation of 0.949 µs. This indicates that the eBPF ingress program introduces a latency of approximately 2.730 µs.

The comparison between kernel-based PDM insertion and eBPF program profiling indicates distinct latencies in packet processing. The kernel approach demonstrates high efficiency with minimal processing time, whereas the eBPF egress and ingress programs introduce noticeable additional latencies. This implies that while eBPF provides flexibility and programmability, it comes at the cost of increased processing time. Consequently, in environments where low latency is crucial, the kernel-based approach might be preferable, whereas eBPF could be more suitable for scenarios where programmability and complex packet processing are prioritized.

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

TODO acknowledge.
