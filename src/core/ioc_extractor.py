import re
import os
import io
import email
import hashlib
import magic
import tldextract
import ipaddress
import socket
import json
import logging
from typing import Dict, List, Union, BinaryIO, Optional, Tuple, Any
from email import policy
from email.parser import BytesParser, Parser
from urllib.parse import urlparse, parse_qs

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IOCExtractor:
    """
    Enhanced IOC Extractor for security analysis.
    
    This class provides comprehensive extraction of Indicators of Compromise (IoCs)
    from various data sources including text, emails, and binary files.
    """
    
    def __init__(self):
        # Regular expressions for different IOC types
        self.patterns = {
            'url': r'https?://(?:[\w-]+\.)+[a-z]{2,}(?:[/?#][^\s"\']*)?',
            'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            # Hash patterns
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'sha512': r'\b[a-fA-F0-9]{128}\b',
            'ssdeep': r'(?:[A-Za-z0-9+\/]|[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=?)',
            
            # Network patterns
            'ipv4': r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'ipv6': r'(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b',
            'url': r'https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)',
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            
            # Security patterns
            'cve': r'\bCVE-\d{4}-\d{4,7}\b',
            'mac_address': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
            'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'yara_rule': r'rule\s+[a-zA-Z0-9_]+\s*\{.*?\}',
            'file_path': r'(?:[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*)|(?:/+(?:[^/\0]+/+)*[^/\0]*)',
            'registry_key': r'(?:HKEY_\w+\\(?:\\[^\\]+)+)',
        }
        
        # Compile regex patterns
        self.regex = {k: re.compile(v, re.IGNORECASE) for k, v in self.patterns.items()}
        
    def extract_from_text(self, text: str, content_type: str = 'text/plain') -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract IOCs from plain text with enhanced processing.
        
        Args:
            text: The text content to analyze
            content_type: MIME type of the content (e.g., 'text/plain', 'text/html')
            
        Returns:
            Dictionary of IOC types and their extracted values with metadata
        """
        if not text or not isinstance(text, str):
            return {}
            
        results = {}
        
        # Process each IOC type
        for ioc_type, pattern in self.regex.items():
            try:
                matches = pattern.findall(text)
                if matches:
                    # Clean, deduplicate, and validate results
                    clean_matches = []
                    for match in matches:
                        if not match or not isinstance(match, str):
                            continue
                            
                        # Clean the match
                        clean_match = match.strip()
                        if not clean_match:
                            continue
                            
                        # Validate based on type
                        if ioc_type == 'ipv4' and not self._is_valid_ipv4(clean_match):
                            continue
                        elif ioc_type == 'ipv6' and not self._is_valid_ipv6(clean_match):
                            continue
                        elif ioc_type == 'domain' and not self._is_valid_domain(clean_match):
                            continue
                        elif ioc_type == 'email' and not self._is_valid_email(clean_match):
                            continue
                            
                        # Add context and metadata
                        clean_matches.append({
                            'value': clean_match,
                            'context': self._get_context(text, clean_match),
                            'position': text.find(clean_match),
                            'source': 'text',
                            'content_type': content_type
                        })
                    
                    if clean_matches:
                        results[ioc_type] = clean_matches
                        
            except Exception as e:
                logger.warning(f"Error processing {ioc_type} IOCs: {str(e)}", exc_info=True)
                continue
                
        # Additional processing for URLs to extract components
        if 'url' in results:
            enriched_urls = []
            for url_data in results['url']:
                url = url_data['value']
                try:
                    parsed = urlparse(url)
                    url_data['components'] = {
                        'scheme': parsed.scheme,
                        'netloc': parsed.netloc,
                        'path': parsed.path,
                        'params': parsed.params,
                        'query': parse_qs(parsed.query),
                        'fragment': parsed.fragment
                    }
                    enriched_urls.append(url_data)
                except Exception as e:
                    logger.warning(f"Error parsing URL {url}: {str(e)}")
                    enriched_urls.append(url_data)
            results['url'] = enriched_urls
            
        return results
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate if a string is a valid domain name."""
        if not domain or len(domain) > 255:
            return False
            
        # Check if it's a valid domain using tldextract
        ext = tldextract.extract(domain)
        if not ext.suffix and not ext.domain:
            return False
            
        # Check each part of the domain
        for part in domain.split('.'):
            if not part or len(part) > 63:
                return False
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$', part):
                return False
                
        return True
        
    def _is_valid_ipv4(self, ip: str) -> bool:
        """Validate IPv4 address."""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
            
    def _is_valid_ipv6(self, ip: str) -> bool:
        """Validate IPv6 address."""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
            
    def _is_valid_email(self, email: str) -> bool:
        """Validate email address format."""
        if not email or '@' not in email:
            return False
            
        local_part, domain_part = email.rsplit('@', 1)
        
        # Validate local part
        if not re.match(r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+$', local_part):
            return False
            
        # Validate domain part
        if not self._is_valid_domain(domain_part):
            return False
            
        return True
        
    def _get_context(self, text: str, match: str, context_size: int = 100) -> str:
        """Extract context around a match in the text."""
        if not text or not match:
            return ""
            
        pos = text.find(match)
        if pos == -1:
            return ""
            
        start = max(0, pos - context_size)
        end = min(len(text), pos + len(match) + context_size)
        
        context = text[start:end]
        if start > 0:
            context = '...' + context
        if end < len(text):
            context = context + '...'
            
        return context
        
    def extract_from_email(self, email_data: Union[bytes, str, BinaryIO]) -> Dict[str, Any]:
        """
        Extract IOCs from an email message with comprehensive analysis.
        
        Args:
            email_data: Email content as bytes, string, or file-like object
            
        Returns:
            Dictionary containing extracted IOCs and email metadata
        """
        results = {
            'iocs': {},
            'metadata': {},
            'headers': {},
            'attachments': []
        }
        
        try:
            # Parse the email
            if isinstance(email_data, (bytes, BinaryIO)):
                msg = email.message_from_bytes(email_data if isinstance(email_data, bytes) else email_data.read(), 
                                            policy=policy.default)
            else:
                msg = email.message_from_string(email_data, policy=policy.default)
                
            # Extract email metadata
            results['metadata'].update({
                'subject': msg.get('subject', ''),
                'from': msg.get('from', ''),
                'to': msg.get('to', ''),
                'date': msg.get('date', ''),
                'message_id': msg.get('message-id', ''),
                'content_type': msg.get_content_type(),
                'content_disposition': msg.get_content_disposition()
            })
            
            # Extract headers
            for header, value in msg.items():
                results['headers'][header] = value
                
            # Process email body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = part.get_content_disposition()
                    
                    # Skip attachments for now (handled separately)
                    if content_disposition == 'attachment':
                        attachment_data = self._process_attachment(part)
                        if attachment_data:
                            results['attachments'].append(attachment_data)
                        continue
                        
                    # Get text content
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            try:
                                charset = part.get_content_charset() or 'utf-8'
                                body += payload.decode(charset, errors='replace')
                            except UnicodeDecodeError:
                                body += payload.decode('latin-1', errors='replace')
                    except Exception as e:
                        logger.warning(f"Error processing email part: {str(e)}")
                        continue
            else:
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        charset = msg.get_content_charset() or 'utf-8'
                        body = payload.decode(charset, errors='replace')
                except Exception as e:
                    logger.warning(f"Error processing email body: {str(e)}")
            
            # Extract IOCs from email body
            if body:
                content_type = msg.get_content_type()
                results['iocs'].update(self.extract_from_text(body, content_type=content_type))
                
            # Extract IOCs from headers
            for header, value in results['headers'].items():
                if isinstance(value, str):
                    header_iocs = self.extract_from_text(value, content_type='email/header')
                    for ioc_type, iocs in header_iocs.items():
                        if ioc_type not in results['iocs']:
                            results['iocs'][ioc_type] = []
                        results['iocs'][ioc_type].extend(iocs)
            
            # Process attachments
            for attachment in results['attachments']:
                if 'iocs' in attachment:
                    for ioc_type, iocs in attachment['iocs'].items():
                        if ioc_type not in results['iocs']:
                            results['iocs'][ioc_type] = []
                        results['iocs'][ioc_type].extend(iocs)
            
            # Deduplicate IOCs
            for ioc_type in results['iocs']:
                unique_iocs = {}
                for ioc in results['iocs'][ioc_type]:
                    unique_iocs[ioc['value']] = ioc
                results['iocs'][ioc_type] = list(unique_iocs.values())
            
        except Exception as e:
            logger.error(f"Error processing email: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to process email: {str(e)}")
            
        return results
    
    def _process_attachment(self, part) -> Dict[str, Any]:
        """
        Process an email attachment and extract IOCs.
        
        Args:
            part: Email message part containing the attachment
            
        Returns:
            Dictionary with attachment metadata and extracted IOCs
        """
        attachment = {
            'filename': part.get_filename() or 'unnamed',
            'content_type': part.get_content_type(),
            'content_disposition': part.get_content_disposition(),
            'size': len(part.get_payload(decode=True)) if part.get_payload() else 0,
            'iocs': {}
        }
        
        try:
            # Get attachment content
            content = part.get_payload(decode=True)
            if not content:
                return attachment
                
            # Calculate file hashes
            attachment['hashes'] = self._calculate_hashes(content)
            
            # Extract IOCs based on content type
            content_type = part.get_content_type()
            
            if content_type.startswith('text/'):
                # Text-based content
                try:
                    charset = part.get_content_charset() or 'utf-8'
                    text_content = content.decode(charset, errors='replace')
                    attachment['iocs'] = self.extract_from_text(text_content, content_type=content_type)
                except Exception as e:
                    logger.warning(f"Error processing text attachment: {str(e)}")
                    
            elif content_type in ['application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed']:
                # Handle archive files (basic handling - could be expanded)
                attachment['iocs']['file_type'] = [{
                    'value': content_type,
                    'source': 'attachment',
                    'content_type': content_type
                }]
                
            else:
                # Binary content - extract basic info
                file_magic = magic.Magic(mime=True)
                detected_type = file_magic.from_buffer(content)
                
                attachment['detected_type'] = detected_type
                
                # If it's a document, try to extract text
                if detected_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                    try:
                        # This is a placeholder - in a real implementation, you'd use a library like python-docx
                        attachment['iocs']['file_type'] = [{
                            'value': detected_type,
                            'source': 'attachment',
                            'content_type': content_type
                        }]
                    except Exception as e:
                        logger.warning(f"Error processing document: {str(e)}")
            
            # Extract IOCs from filename
            filename_iocs = self.extract_from_text(attachment['filename'], content_type='filename')
            for ioc_type, iocs in filename_iocs.items():
                if ioc_type not in attachment['iocs']:
                    attachment['iocs'][ioc_type] = []
                attachment['iocs'][ioc_type].extend(iocs)
                
        except Exception as e:
            logger.error(f"Error processing attachment {attachment.get('filename', 'unknown')}: {str(e)}", exc_info=True)
            attachment['error'] = str(e)
            
        return attachment
        
    def _calculate_hashes(self, data: bytes) -> Dict[str, str]:
        """Calculate various hash digests for binary data."""
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'sha512': hashlib.sha512(data).hexdigest(),
            'ssdeep': self._calculate_ssdeep(data) if hasattr(self, '_calculate_ssdeep') else None
        }
        
    def extract_from_file(self, file_path: str) -> Dict[str, Any]:
        """
        Extract IOCs from a file on disk.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing file metadata and extracted IOCs
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        results = {
            'file_path': os.path.abspath(file_path),
            'file_name': os.path.basename(file_path),
            'file_size': os.path.getsize(file_path),
            'file_type': magic.Magic(mime=True).from_file(file_path),
            'iocs': {}
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Calculate file hashes
            results['hashes'] = self._calculate_hashes(content)
            
            # Extract IOCs from filename
            filename_iocs = self.extract_from_text(results['file_name'], content_type='filename')
            results['iocs'].update(filename_iocs)
            
            # Extract IOCs from file content based on file type
            if results['file_type'].startswith('text/'):
                try:
                    text_content = content.decode('utf-8', errors='replace')
                    content_iocs = self.extract_from_text(text_content, content_type=results['file_type'])
                    for ioc_type, iocs in content_iocs.items():
                        if ioc_type not in results['iocs']:
                            results['iocs'][ioc_type] = []
                        results['iocs'][ioc_type].extend(iocs)
                except Exception as e:
                    logger.warning(f"Error processing text content: {str(e)}")
                    
            # Add more file type specific processing here as needed
            
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}", exc_info=True)
            results['error'] = str(e)
            
        return results

# Singleton instance
ioc_extractor = IOCExtractor()
