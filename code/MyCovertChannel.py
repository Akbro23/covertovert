from scapy.all import IP, TCP, sniff
from random import randint
from CovertChannelBase import CovertChannelBase


class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def send(self, log_file_name, packets_per_bit, bit_one_threshold):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        
        for bit in binary_message:
            if bit == '0':
                num = randint(0, bit_one_threshold - 1)
            elif bit == '1':
                num = randint(bit_one_threshold, 2**packets_per_bit - 1)
                
            binary_num = format(num, f'0{packets_per_bit}b')

            for b in binary_num:
                packet = IP(dst='receiver')/TCP(flags='F' if b == '1' else '')
                super().send(packet)

        
    def receive(self, log_file_name, packets_per_bit, bit_one_threshold):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        message = ''
        byte = ''
        bits = ''
        packet_counter = 0
        threshold = format(bit_one_threshold, f'0{packets_per_bit}b')
        def decode_fin_covert_message(packet):
            nonlocal message, byte, bits, packet_counter
            
            if TCP in packet: 
                packet_counter += 1
                if packet_counter % 2 == 0:
                    return 
                
                if packet[TCP].flags.F:
                    bits += '1'
                else:
                    bits += '0'

                if len(bits) == packets_per_bit:
                    if bits < threshold:
                        byte += '0'
                    else:
                        byte += '1'
                    bits = ''

                if len(byte) == 8:
                    char = chr(int(byte, 2))
                    byte = ''
                    message += char

                    if char == '.':
                        self.log_message(message, log_file_name)
                        exit()


        sniff(filter="tcp", prn=decode_fin_covert_message)
            


