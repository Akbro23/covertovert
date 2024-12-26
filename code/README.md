# Covert Storage Channel that exploits Protocol Field Manipulation using FIN Flag field in TCP [Code: CSC-PSV-TCP-FIN]

In this project, we use the TCP FIN flag to transmit messages covertly. The transmission is based on encoding a number into multiple packets using the FIN flag. 

- **If the encoded number is less than the threshold**, it is treated as `0`.  
- **If the number is greater than or equal to the threshold**, it is treated as `1`.

The parameters `packets_per_bit` (number of packets used to encode a single bit) and `bit_one_threshold` (threshold for differentiating between `0` and `1`) are known beforehand by both the sender and the receiver.

---

### How It Works

1. **Encoding Bit `0`**:
   - The sender randomly generates a number between `0` and `bit_one_threshold - 1`.
   - This number is encoded into packets using the FIN flag.
   
2. **Encoding Bit `1`**:
   - The sender randomly generates a number between `bit_one_threshold` and `2 ^ packets_per_bit - 1`.
   - This number is similarly encoded into packets.

3. **Transmission**:
   - The sender transmits each bit of the encoded number as a packet:
     - **If the bit is `1`**, the TCP packet is sent with the FIN flag set.
     - **If the bit is `0`**, the TCP packet is sent without the FIN flag.

4. **Decoding**:
   - The receiver collects the transmitted packets and combines the bits.
   - Based on the known parameters `packets_per_bit` and `bit_one_threshold`, the receiver decodes the packets to regenerate the original message.

---

### Parameter constraints
- `packets_per_bit` ≥ 2

  **Explanation**: the bits of a message should not be directly transmitted through the FIN flag, thus at least 2 packets should be used for a single bit of the message.

- 0 < `bit_one_threshold` < 2 ^ `packets_per_bit`. 

  **Explanation**: there should be at least one number to encode either bit `1` or bit `0`.

---

### Channel capacity
To test the capacity of the channel, a binary message whose length is 128 bits was used. The time interval between sending the first and the last packet was measured to find the capacity. Additinally, the used `packets_per_bit` was 2, so the measured capacity provides the upper bound. Thus, if `packets_per_bit` increases, the capacity should be expected to decrease.
- message length: 128 bits
- measured time: 21.79 seconds
- measured capacity = 128 / 21.79 ≈ 5.87 bits/second
