"""
utils/file_integrity.py
=======================
File Integrity Checker using cryptographic hashing.

CYBERSECURITY CONCEPTS:
- Hashing: One-way function that produces a fixed-size output (digest) from any input
- SHA-256: Secure Hash Algorithm producing 256-bit hash, part of SHA-2 family
- Digital Fingerprint: Unique identifier for file content, any change = different hash
- Integrity Verification: Comparing hashes to detect unauthorized modifications
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Optional


class FileIntegrityChecker:
    """
    Handles file hashing and integrity verification.
    
    SHA-256 is used because:
    1. Collision-resistant: Extremely unlikely two files produce same hash
    2. Pre-image resistant: Cannot reverse-engineer original file from hash
    3. Industry standard: Used in TLS, code signing, blockchain
    """
    
    def __init__(self, hashes_folder: Path):
        """
        Initialize the checker with a storage location for hash records.
        
        Args:
            hashes_folder: Directory to store hash JSON files
        """
        self.hashes_folder = Path(hashes_folder)
        self.hashes_folder.mkdir(parents=True, exist_ok=True)
    
    def calculate_hash(self, file_path: Path, algorithm: str = 'sha256') -> dict:
        """
        Calculate cryptographic hash of a file.
        
        Uses chunked reading to handle large files without loading
        entire content into memory—important for security tools that
        may process multi-gigabyte files.
        
        Args:
            file_path: Path to the file to hash
            algorithm: Hash algorithm ('sha256', 'md5', 'sha1')
            
        Returns:
            Dictionary containing hash and file metadata
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Select hash algorithm
        # SHA-256 is default; MD5/SHA-1 included for legacy compatibility
        hash_func = hashlib.new(algorithm)
        
        # Read file in 8KB chunks to handle large files efficiently
        # This prevents memory exhaustion attacks
        chunk_size = 8192
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                hash_func.update(chunk)
        
        # Get file statistics
        file_stat = file_path.stat()
        
        return {
            'filename': file_path.name,
            'filepath': str(file_path),
            'hash_value': hash_func.hexdigest(),
            'algorithm': algorithm.upper(),
            'file_size': file_stat.st_size,
            'file_size_formatted': self._format_size(file_stat.st_size),
            'created_at': datetime.now().isoformat(),
            'modified_time': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
        }
    
    def save_hash(self, hash_data: dict) -> str:
        """
        Save hash record to JSON file for later verification.
        
        Storing hashes separately from files allows detection of
        unauthorized modifications—a core principle in file integrity
        monitoring (FIM) systems used by security teams.
        
        Args:
            hash_data: Dictionary containing hash and metadata
            
        Returns:
            Path to saved hash record
        """
        # Create unique filename using original name and timestamp
        safe_filename = "".join(c if c.isalnum() else "_" for c in hash_data['filename'])
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        record_name = f"{safe_filename}_{timestamp}.json"
        record_path = self.hashes_folder / record_name
        
        with open(record_path, 'w') as f:
            json.dump(hash_data, f, indent=2)
        
        return str(record_path)
    
    def verify_integrity(self, file_path: Path, original_hash: str, 
                         algorithm: str = 'sha256') -> dict:
        """
        Verify file integrity by comparing current hash against stored hash.
        
        This is how security tools detect:
        - Malware infections that modify executables
        - Unauthorized configuration changes
        - Data tampering
        - Rootkit installations
        
        Args:
            file_path: Path to file to verify
            original_hash: Previously recorded hash value
            algorithm: Hash algorithm used for original hash
            
        Returns:
            Verification result with status and details
        """
        current_data = self.calculate_hash(file_path, algorithm)
        current_hash = current_data['hash_value']
        
        is_intact = current_hash.lower() == original_hash.lower()
        
        return {
            'filename': current_data['filename'],
            'is_intact': is_intact,
            'status': 'INTEGRITY_MAINTAINED' if is_intact else 'FILE_MODIFIED',
            'risk_level': 'safe' if is_intact else 'high',
            'original_hash': original_hash,
            'current_hash': current_hash,
            'algorithm': algorithm.upper(),
            'verified_at': datetime.now().isoformat(),
            'message': (
                'File integrity verified. No modifications detected.'
                if is_intact else
                'WARNING: File has been modified! Hash mismatch detected.'
            )
        }
    
    def get_saved_hashes(self) -> list:
        """
        Retrieve all saved hash records.
        
        Returns:
            List of hash records with metadata
        """
        records = []
        for hash_file in self.hashes_folder.glob('*.json'):
            try:
                with open(hash_file) as f:
                    data = json.load(f)
                    data['record_file'] = hash_file.name
                    records.append(data)
            except json.JSONDecodeError:
                continue  # Skip corrupted files
        
        # Sort by creation date, newest first
        records.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return records
    
    def generate_report(self, hash_data: dict, reports_folder: Path) -> str:
        """
        Generate a downloadable integrity report.
        
        Professional security reports include:
        - Clear identification of the file
        - Hash values for verification
        - Timestamps for audit trails
        - Methodology description
        
        Args:
            hash_data: Hash information to include
            reports_folder: Directory to save report
            
        Returns:
            Path to generated report
        """
        reports_folder = Path(reports_folder)
        reports_folder.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_name = f"integrity_report_{timestamp}.txt"
        report_path = reports_folder / report_name
        
        report_content = f"""
╔══════════════════════════════════════════════════════════════════╗
║              CYBERSHIELD FILE INTEGRITY REPORT                   ║
╠══════════════════════════════════════════════════════════════════╣
║  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
╚══════════════════════════════════════════════════════════════════╝

FILE INFORMATION
================
Filename:     {hash_data.get('filename', 'N/A')}
File Size:    {hash_data.get('file_size_formatted', 'N/A')}
Modified:     {hash_data.get('modified_time', 'N/A')}

HASH DETAILS
============
Algorithm:    {hash_data.get('algorithm', 'SHA-256')}
Hash Value:   {hash_data.get('hash_value', 'N/A')}

VERIFICATION STATUS
===================
Status:       {hash_data.get('status', 'HASH_GENERATED')}
Risk Level:   {hash_data.get('risk_level', 'N/A').upper()}

METHODOLOGY
===========
This report was generated using SHA-256 cryptographic hashing.
SHA-256 produces a 256-bit (32-byte) hash value, typically rendered
as a 64-character hexadecimal string. Any modification to the file,
no matter how small, will result in a completely different hash.

RECOMMENDATIONS
===============
1. Store this hash value securely for future verification
2. Re-verify files before executing or opening them
3. Compare hashes when downloading files from the internet
4. Use file integrity monitoring for critical system files

══════════════════════════════════════════════════════════════════
                    CyberShield Security Suite
══════════════════════════════════════════════════════════════════
"""
        
        with open(report_path, 'w') as f:
            f.write(report_content)
        
        return str(report_path)
    
    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} TB"
