from typing import Dict, List, Any
import re
import pyshark
import asyncio
from datetime import datetime

class AttackAnalyzer:
    def __init__(self):
        self.attack_patterns = {
            'initial_access': {
                'pattern': r'(?i)(password spray|brute force|exploit)',
                'technique_id': 'T1190'
            },
            'execution': {
                'pattern': r'(?i)(powershell|cmd.exe|script)',
                'technique_id': 'T1059'
            },
            'dangerous_protocols': {
                'pattern': r'(?i)(telnet|ftp)',
                'technique_id': 'T1071'
            },
            'suspicious_traffic': {
                'pattern': r'(?i)(backdoor|trojan|malware)',
                'technique_id': 'T1505'
            }
        }

    def analyze_pcap(self, pcap_file: str) -> Dict:
        # Create new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            cap = pyshark.FileCapture(pcap_file)
            results = {
                'status': 'good',
                'timestamp': datetime.now().isoformat(),
                'alerts': [],
                'statistics': {
                    'total_packets': 0,
                    'suspicious_packets': 0,
                    'protocols': {}
                }
            }

            # Process packets
            for packet in cap:
                results['statistics']['total_packets'] += 1
                
                try:
                    protocol = packet.highest_layer
                    results['statistics']['protocols'][protocol] = results['statistics']['protocols'].get(protocol, 0) + 1
                    
                    if protocol in ['TELNET', 'FTP']:
                        results['alerts'].append({
                            'severity': 'high',
                            'message': f'Dangerous protocol detected: {protocol}',
                            'packet_number': packet.number
                        })
                        results['status'] = 'dangerous'
                    
                    if hasattr(packet, 'payload'):
                        payload = str(packet.payload)
                        for category, config in self.attack_patterns.items():
                            if re.search(config['pattern'], payload):
                                results['alerts'].append({
                                    'severity': 'high',
                                    'category': category,
                                    'technique_id': config['technique_id'],
                                    'message': f'Suspicious pattern detected in packet {packet.number}',
                                    'source': packet.ip.src if hasattr(packet, 'ip') else 'unknown'
                                })
                                results['status'] = 'dangerous'
                                results['statistics']['suspicious_packets'] += 1
                    
                except Exception as e:
                    continue

            cap.close()
            
            if results['statistics']['suspicious_packets'] > 0:
                results['status'] = 'dangerous'
            elif len(results['alerts']) > 0:
                results['status'] = 'suspicious'
                
            return results
            
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }
        finally:
            loop.close()
