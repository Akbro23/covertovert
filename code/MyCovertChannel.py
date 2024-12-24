from scapy.all import IP, TCP, sniff
from random import randint
from CovertChannelBase import CovertChannelBase


class MyCovertChannel(CovertChannelBase):

    def send(self, log_file_name, packets_per_bit, bit_one_threshold):
        '''
        Arguments:
        - `log_file_name` (str): The name of the log file where the message encoding process is logged. This allows tracking of the steps during the transmission.
        - `packets_per_bit` (int): The number of packets used to encode each bit of the original message. This determines the length of the binary encoding for each bit.
        - `bit_one_threshold` (int): The threshold value used to differentiate between encoding a '0' or a '1'. 
            - If the randomly generated integer is less than the threshold, it is encoded as a '0'.
            - If the randomly generated integer is greater than or equal to the threshold, it is encoded as a '1'.

        Returns:
        - None: This function does not return any value. Instead, it transmits the encoded message as TCP packets and does not stop until the message has been completely sent.

        Implementation of the `send` function:
            1. Convert the original message into a binary string.

            2. For each bit in the binary message:
                - If the bit is '0', generate a random integer in the range [0, `bit_one_threshold`).
                - If the bit is '1', generate a random integer in the range [`bit_one_threshold`, 2 ** `packets_per_bit`).

            3. Encode the integer as a binary string of length `packets_per_bit`.

            4. Transmit each bit as a separate TCP packet:
                - Use the `FIN` flag to indicate a '1' bit and no flag for a '0' bit.
        '''
        assert packets_per_bit >= 2, 'Number of packets per bit must be at least 2.'
        assert 0 < bit_one_threshold < 2 ** packets_per_bit, 'Threshold for encoding bit "1" must be between 0 and 2 ** `packets_per_bit`.'

        # Generate a random binary message and log it to the specified file
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        
        for bit in binary_message:
            # Encode the bit based on its value ('0' or '1')
            if bit == '0':
                # Generate a random integer in the range [0, `bit_one_threshold`)
                num = randint(0, bit_one_threshold - 1)
            elif bit == '1':
                # Generate a random integer in the range [`bit_one_threshold`, 2 ** `packets_per_bit`)
                num = randint(bit_one_threshold, 2 ** packets_per_bit - 1)
            
            # Encode this integer as a binary string of length `packets_per_bit`
            binary_num = format(num, f'0{packets_per_bit}b')

            # Send each bit of the encoded binary string as a separate packet
            for b in binary_num:
                # The `FIN` flag is used for the transmission of a bit.
                packet = IP(dst='receiver')/TCP(flags='F' if b == '1' else '')
                super().send(packet)

        
    def receive(self, log_file_name, packets_per_bit, bit_one_threshold):
        '''
        Arguments:
        - `log_file_name` (str): The name of the log file where the final decoded message will be written. The message is logged once a dot ('.') is received in the message.
        - `packets_per_bit` (int): The number of packets used to encode each bit of the original message. This defines how many bits are accumulated before they are compared and decoded into a bit ('0' or '1').
        - `bit_one_threshold` (int): The threshold value used to determine whether a set of accumulated bits represents a '0' or '1'. 
            - If the accumulated bits are less than this threshold, it is decoded as '0'.
            - If the accumulated bits are greater than or equal to the threshold, it is decoded as '1'.
            
        Returns:
        - None: This function does not return any value. Instead, it logs the decoded message to a file and stops when a dot character is encountered.
        
        This function uses the following variables to decode the transmitted message:
        - `bits`: accumulates bits (from TCP packets) to reconstruct the original message's bits.
        - `byte`: accumulates 8 bits to form a byte (character) of the original message.
        - `message`: accumulates characters to form the entire message, ending when a dot character is received.
            
        The process includes:
            1. Sniffing for TCP packets coming from the sender.

            2. Determining whether each packet represents a '1' or '0' bit:
                - If the TCP packet has the FIN flag set, treat it as a '1' bit.
                - Otherwise, treat it as a '0' bit.
                
            3. Once `packets_per_bit` bits are collected, decide if it's a '0' or '1' bit of the message:
                - If it is less than `bit_one_threshold`, treat it as '0' bit.
                - Otherwise, treat it as '1' bit.

            4. When 8 bits of the message are collected (forming a byte):
                - Convert the byte to a character.
                - Add the character to the message.
                - Stop if the character is a dot ('.') and log the final message.
        '''
        assert packets_per_bit >= 2, 'Number of packets per bit must be at least 2.'
        assert 0 < bit_one_threshold < 2 ** packets_per_bit, 'Threshold for encoding bit "1" must be between 0 and 2 ** packets_per_bit.'

        bits = ''  # String to accumulate bits for the current packet
        byte = ''  # String to accumulate 8 bits of the message
        message = ''  # String to accumulate the entire decoded message
        threshold = format(bit_one_threshold, f'0{packets_per_bit}b')  # Convert the threshold to a binary string

        # Function to decode each packet
        def decode_fin_covert_message(packet):
            nonlocal bits, byte, message
            
            # Check if the FIN flag is set in the packet
            if packet[TCP].flags.F:
                bits += '1'  # If FIN flag is set, add '1' to the accumulated bits
            else:
                bits += '0'  # Otherwise, add '0'

            # Once `packets_per_bit` bits are collected, decide if it's a '0' or '1' bit of the message
            if len(bits) == packets_per_bit:
                if bits < threshold:
                    byte += '0'  # If bits are below the threshold, add '0' to the byte.
                else:
                    byte += '1'  # Otherwise, add '1' to the byte.
                bits = ''  # Reset bits for the next bit of the message.

            # Once 8 bits of the message are accumulated, form a character and add it to the message.
            if len(byte) == 8:
                char = chr(int(byte, 2))  # Convert the byte (binary string) to a character.
                byte = ''  # Reset byte for the next character.
                message += char  # Add the character to the message.

                # If the character is a dot, stop the communication and log the message.
                if char == '.':
                    self.log_message(message, log_file_name)
                    exit()  # Stop receiving further packets once the message is complete.

        # Sniff for TCP packets coming from the 'sender' host.
        sniff(filter='src host sender and tcp', prn=decode_fin_covert_message)

