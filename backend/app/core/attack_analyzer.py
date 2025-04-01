from typing import Dict, List, Any
import re
import pyshark
import asyncio
from datetime import datetime
from collections import Counter, defaultdict
import logging

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

    def _extract_packet_details(self, packet) -> dict:
        """Extract detailed information from packet"""
        details = {
            'info': getattr(packet, 'info', 'No info available'),
            'length': getattr(packet, 'length', '0'),
            'protocol': packet.highest_layer,
            'time': getattr(packet, 'sniff_time', datetime.now()).isoformat(),
            'details': {}
        }

        # Extract protocol specific details
        if hasattr(packet, 'tcp'):
            details['details']['tcp'] = {
                'stream': getattr(packet.tcp, 'stream', ''),
                'flags': getattr(packet.tcp, 'flags', ''),
                'port': f"{getattr(packet.tcp, 'srcport', '')} → {getattr(packet.tcp, 'dstport', '')}"
            }

        if hasattr(packet, 'http'):
            details['details']['http'] = {
                'method': getattr(packet.http, 'request_method', ''),
                'uri': getattr(packet.http, 'request_uri', ''),
                'user_agent': getattr(packet.http, 'user_agent', '')
            }

        if hasattr(packet, 'dns'):
            details['details']['dns'] = {
                'qry_name': getattr(packet.dns, 'qry_name', ''),
                'resp_name': getattr(packet.dns, 'resp_name', '')
            }

        return details

    def analyze_pcap(self, pcap_file: str) -> Dict:
        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger(__name__)
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            logger.debug(f"Starting analysis of {pcap_file}")
            cap = pyshark.FileCapture(pcap_file)
            results = {
                'status': 'good',
                'timestamp': datetime.now().isoformat(),
                'alerts': [],
                'statistics': {
                    'total_packets': 0,
                    'suspicious_packets': 0,
                    'total_attacks': 0,
                    'attack_details': [],
                    'protocols': {},
                    'ip_addresses': {
                        'sources': {},
                        'destinations': {},
                        'top_talkers': [],
                        'unique_count': 0,
                        'total_count': 0,
                        'attackers': defaultdict(int),
                        'victims': defaultdict(int)
                    }
                }
            }

            unique_ips = set()
            packet_count = 0
            for packet in cap:
                packet_count += 1
                results['statistics']['total_packets'] += 1
                
                try:
                    if not hasattr(packet, 'ip'):
                        continue

                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    logger.debug(f"Processing packet {packet_count}: {src_ip} -> {dst_ip}")

                    unique_ips.add(src_ip)
                    unique_ips.add(dst_ip)
                    
                    results['statistics']['ip_addresses']['sources'][src_ip] = \
                        results['statistics']['ip_addresses']['sources'].get(src_ip, 0) + 1
                    results['statistics']['ip_addresses']['destinations'][dst_ip] = \
                        results['statistics']['ip_addresses']['destinations'].get(dst_ip, 0) + 1
                    
                    protocol = packet.highest_layer
                    logger.debug(f"Protocol: {protocol}")

                    # Extract packet details
                    packet_details = self._extract_packet_details(packet)
                    
                    # Add packet details to results
                    if 'packets' not in results:
                        results['packets'] = []
                    
                    results['packets'].append({
                        'number': packet.number,
                        'source': packet.ip.src,
                        'destination': packet.ip.dst,
                        'protocol': packet.highest_layer,
                        'info': packet_details['info'],
                        'length': packet_details['length'],
                        'time': packet_details['time'],
                        'details': packet_details['details']
                    })
                    
                    if protocol in ['TELNET', 'FTP']:
                        logger.debug(f"Found dangerous protocol: {protocol}")
                        self._record_attack(results, src_ip, dst_ip, {
                            'type': 'dangerous_protocol',
                            'protocol': protocol,
                            'packet_number': packet.number,
                            'timestamp': getattr(packet, 'sniff_time', datetime.now()).isoformat()
                        })

                    if hasattr(packet, 'payload'):
                        payload = str(packet.payload)
                        for category, config in self.attack_patterns.items():
                            if re.search(config['pattern'], payload):
                                logger.debug(f"Found attack pattern: {category}")
                                self._record_attack(results, src_ip, dst_ip, {
                                    'type': 'pattern_match',
                                    'category': category,
                                    'technique_id': config['technique_id'],
                                    'packet_number': packet.number,
                                    'timestamp': getattr(packet, 'sniff_time', datetime.now()).isoformat()
                                })
                    
                except Exception as e:
                    logger.error(f"Error processing packet: {str(e)}")
                    continue

            logger.debug(f"Analysis complete. Total packets: {packet_count}")
            logger.debug(f"Attacks found: {results['statistics']['total_attacks']}")
            
            results['statistics']['ip_addresses']['unique_count'] = len(unique_ips)

            all_ips = Counter(results['statistics']['ip_addresses']['sources'])
            all_ips.update(Counter(results['statistics']['ip_addresses']['destinations']))
            results['statistics']['ip_addresses']['top_talkers'] = [
                {'ip': ip, 'count': count} 
                for ip, count in all_ips.most_common(10)
            ]

            self._update_summaries(results)
            
            if results['statistics']['suspicious_packets'] > 0:
                results['status'] = 'dangerous'
            elif len(results['alerts']) > 0:
                results['status'] = 'suspicious'
                
            return results
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
        finally:
            loop.close()

    def _record_attack(self, results, src_ip, dst_ip, attack_info):
        """Helper method to record an attack"""
        results['statistics']['total_attacks'] += 1
        results['statistics']['ip_addresses']['attackers'][src_ip] += 1
        results['statistics']['ip_addresses']['victims'][dst_ip] += 1
        
        attack_detail = {
            'attacker': src_ip,
            'victim': dst_ip,
            **attack_info
        }
        
        # Add packet details to attack record if available
        if 'packet_number' in attack_info and results.get('packets'):
            for packet in results['packets']:
                if packet['number'] == attack_info['packet_number']:
                    attack_detail['packet_info'] = packet['info']
                    attack_detail['packet_details'] = packet['details']
                    break

        results['statistics']['attack_details'].append(attack_detail)
        results['status'] = 'dangerous'

    def _update_summaries(self, results):
        """Helper method to update attack summaries"""
        attackers = results['statistics']['ip_addresses']['attackers']
        victims = results['statistics']['ip_addresses']['victims']
        
        results['statistics']['attack_summary'] = {
            'total_attacks': results['statistics']['total_attacks'],
            'top_attackers': [
                {'ip': ip, 'attacks': count} 
                for ip, count in sorted(attackers.items(), key=lambda x: x[1], reverse=True)[:5]
            ],
            'top_victims': [
                {'ip': ip, 'times_targeted': count} 
                for ip, count in sorted(victims.items(), key=lambda x: x[1], reverse=True)[:5]
            ]
        }
