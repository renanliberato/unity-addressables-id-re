#!/usr/bin/env python3
"""
Unity Addressables Catalog Parser
Parses catalog.json files and outputs asset GUID to bundle/path mappings
"""

import json
import base64
import struct
import sys
from typing import Dict, List, Tuple, Any
from collections import defaultdict


class UnitySerializer:
    """Handles Unity serialization format for objects in byte arrays"""
    
    @staticmethod
    def read_int32(data: bytes, offset: int) -> Tuple[int, int]:
        """Read Int32 from byte array, return (value, bytes_read)"""
        value = struct.unpack_from('<i', data, offset)[0]
        return value, 4
    
    @staticmethod
    def read_object(data: bytes, offset: int) -> Tuple[Any, int]:
        """
        Read a serialized Unity object from byte array.
        Unity serializes objects with a type byte followed by the data.
        Returns (object, bytes_read)
        """
        if offset >= len(data):
            return None, 0
            
        # Read type byte
        type_byte = data[offset]
        current_offset = offset + 1
        
        # Type 0: Null
        if type_byte == 0:
            return None, 1
        
        # Type 1: String
        elif type_byte == 1:
            # Read string length (7-bit encoded)
            length, length_size = UnitySerializer._read_7bit_encoded_int(data, current_offset)
            current_offset += length_size
            
            # Read string bytes
            str_bytes = data[current_offset:current_offset + length]
            current_offset += length
            
            try:
                string_val = str_bytes.decode('utf-8')
            except:
                string_val = str(str_bytes)
            
            return string_val, current_offset - offset
        
        # Type 2: Int32
        elif type_byte == 2:
            value, size = UnitySerializer.read_int32(data, current_offset)
            return value, size + 1
        
        # For other types, try to read as string (most keys are strings)
        else:
            # Assume it's a string with different encoding
            try:
                length, length_size = UnitySerializer._read_7bit_encoded_int(data, current_offset)
                current_offset += length_size
                str_bytes = data[current_offset:current_offset + length]
                string_val = str_bytes.decode('utf-8')
                return string_val, current_offset + length - offset
            except:
                return None, 1
    
    @staticmethod
    def _read_7bit_encoded_int(data: bytes, offset: int) -> Tuple[int, int]:
        """Read a 7-bit encoded integer (used for string lengths)"""
        result = 0
        bytes_read = 0
        shift = 0
        
        while True:
            if offset + bytes_read >= len(data):
                return result, bytes_read
                
            byte_val = data[offset + bytes_read]
            bytes_read += 1
            
            result |= (byte_val & 0x7F) << shift
            shift += 7
            
            if (byte_val & 0x80) == 0:
                break
        
        return result, bytes_read


class AddressablesCatalogParser:
    """Parses Unity Addressables catalog.json files"""
    
    def __init__(self, catalog_path: str):
        self.catalog_path = catalog_path
        self.catalog_data = None
        self.keys = []
        self.internal_ids = []
        self.provider_ids = []
        self.resource_types = []
        self.buckets = []
        self.locations = []
        
    def load_catalog(self) -> bool:
        """Load and parse the catalog.json file"""
        try:
            with open(self.catalog_path, 'r', encoding='utf-8') as f:
                self.catalog_data = json.load(f)
            return True
        except Exception as e:
            print(f"Error loading catalog: {e}")
            return False
    
    def parse_catalog(self) -> bool:
        """Parse the catalog data structures"""
        if not self.catalog_data:
            return False
        
        try:
            # Extract basic arrays
            self.internal_ids = self.catalog_data.get('m_InternalIds', [])
            self.provider_ids = self.catalog_data.get('m_ProviderIds', [])
            
            # Parse resource types
            resource_types_data = self.catalog_data.get('m_resourceTypes', [])
            self.resource_types = []
            for rt in resource_types_data:
                if isinstance(rt, dict):
                    # Extract the class name from the serialized type
                    class_str = rt.get('m_ClassName', 'Unknown')
                    # Parse type string like "UnityEngine.GameObject, UnityEngine"
                    type_name = class_str.split(',')[0].split('.')[-1] if '.' in class_str else class_str
                    self.resource_types.append(type_name)
                else:
                    self.resource_types.append(str(rt))
            
            # Decode bucket data
            self._parse_buckets()
            
            # Decode key data
            self._parse_keys()
            
            # Decode entry data
            self._parse_entries()
            
            return True
        except Exception as e:
            print(f"Error parsing catalog: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _parse_buckets(self):
        """Parse bucket data (key to entry mappings)"""
        bucket_data_str = self.catalog_data.get('m_BucketDataString', '')
        if not bucket_data_str:
            return
        
        bucket_data = base64.b64decode(bucket_data_str)
        
        # Read bucket count
        bucket_count = struct.unpack_from('<i', bucket_data, 0)[0]
        offset = 4
        
        self.buckets = []
        for i in range(bucket_count):
            # Read data offset (index into key data)
            data_offset = struct.unpack_from('<i', bucket_data, offset)[0]
            offset += 4
            
            # Read entry count
            entry_count = struct.unpack_from('<i', bucket_data, offset)[0]
            offset += 4
            
            # Read entry indices
            entries = []
            for j in range(entry_count):
                entry_idx = struct.unpack_from('<i', bucket_data, offset)[0]
                entries.append(entry_idx)
                offset += 4
            
            self.buckets.append({
                'data_offset': data_offset,
                'entries': entries
            })
    
    def _parse_keys(self):
        """Parse key data (GUIDs, addresses, labels)"""
        key_data_str = self.catalog_data.get('m_KeyDataString', '')
        if not key_data_str:
            return
        
        key_data = base64.b64decode(key_data_str)
        
        # Read key count
        key_count = struct.unpack_from('<i', key_data, 0)[0]
        
        self.keys = []
        for bucket in self.buckets:
            offset = bucket['data_offset']
            try:
                type_byte = key_data[offset]
                offset += 1
                
                if type_byte == 0:
                    # Type 0: String with 4-byte int32 length prefix
                    length = struct.unpack_from('<i', key_data, offset)[0]
                    offset += 4
                    key_str = key_data[offset:offset + length].decode('utf-8', errors='ignore')
                    self.keys.append(key_str)
                elif type_byte == 1:
                    # Type 1: String with 7-bit encoded length
                    length = 0
                    shift = 0
                    while True:
                        byte_val = key_data[offset]
                        offset += 1
                        length |= (byte_val & 0x7F) << shift
                        if (byte_val & 0x80) == 0:
                            break
                        shift += 7
                    key_str = key_data[offset:offset + length].decode('utf-8', errors='ignore')
                    self.keys.append(key_str)
                elif type_byte == 4:
                    # Type 4: Seems to be int32 or special marker
                    # Skip this for now, use empty string
                    self.keys.append("")
                else:
                    # Unknown type, use empty string
                    self.keys.append("")
            except Exception as e:
                # If parsing fails, append empty string
                self.keys.append("")
    
    def _parse_entries(self):
        """Parse entry data (location information)"""
        entry_data_str = self.catalog_data.get('m_EntryDataString', '')
        if not entry_data_str:
            return
        
        entry_data = base64.b64decode(entry_data_str)
        
        # Constants from Unity code
        BYTES_PER_INT32 = 4
        ENTRY_DATA_ITEM_PER_ENTRY = 7
        
        # Read entry count
        entry_count = struct.unpack_from('<i', entry_data, 0)[0]
        
        self.locations = []
        for i in range(entry_count):
            offset = BYTES_PER_INT32 + i * (BYTES_PER_INT32 * ENTRY_DATA_ITEM_PER_ENTRY)
            
            # Read entry data (7 int32 values)
            internal_id_idx = struct.unpack_from('<i', entry_data, offset)[0]
            offset += BYTES_PER_INT32
            
            provider_idx = struct.unpack_from('<i', entry_data, offset)[0]
            offset += BYTES_PER_INT32
            
            dependency_key_idx = struct.unpack_from('<i', entry_data, offset)[0]
            offset += BYTES_PER_INT32
            
            dep_hash = struct.unpack_from('<i', entry_data, offset)[0]
            offset += BYTES_PER_INT32
            
            data_idx = struct.unpack_from('<i', entry_data, offset)[0]
            offset += BYTES_PER_INT32
            
            primary_key_idx = struct.unpack_from('<i', entry_data, offset)[0]
            offset += BYTES_PER_INT32
            
            resource_type_idx = struct.unpack_from('<i', entry_data, offset)[0]
            
            # Build location object
            location = {
                'internal_id': self.internal_ids[internal_id_idx] if internal_id_idx < len(self.internal_ids) else None,
                'provider': self.provider_ids[provider_idx] if provider_idx < len(self.provider_ids) else None,
                'primary_key': self.keys[primary_key_idx] if primary_key_idx < len(self.keys) else None,
                'resource_type': self.resource_types[resource_type_idx] if resource_type_idx < len(self.resource_types) else None,
                'has_dependencies': dependency_key_idx >= 0,
                'dependency_key': self.keys[dependency_key_idx] if dependency_key_idx >= 0 and dependency_key_idx < len(self.keys) else None,
            }
            
            self.locations.append(location)
    
    def get_asset_mappings(self) -> Dict[str, Dict[str, Any]]:
        """
        Get mappings from asset keys (GUIDs/addresses) to their location data.
        Returns a dict: {key: {internal_id, provider, resource_type, dependencies}}
        """
        mappings = defaultdict(list)
        
        for bucket_idx, bucket in enumerate(self.buckets):
            if bucket_idx >= len(self.keys):
                continue
                
            key = self.keys[bucket_idx]
            if not key:
                continue
            
            for entry_idx in bucket['entries']:
                if entry_idx < len(self.locations):
                    location = self.locations[entry_idx]
                    mappings[str(key)].append(location)
        
        return dict(mappings)
    
    def print_summary(self):
        """Print a summary of the catalog contents"""
        print(f"\n{'='*70}")
        print(f"Catalog Summary: {self.catalog_data.get('m_LocatorId', 'Unknown')}")
        print(f"{'='*70}")
        print(f"Total Keys: {len(self.keys)}")
        print(f"Total Locations: {len(self.locations)}")
        print(f"Total Internal IDs (bundles): {len(self.internal_ids)}")
        print(f"Total Providers: {len(self.provider_ids)}")
        print(f"Total Resource Types: {len(self.resource_types)}")
        print(f"{'='*70}\n")
    
    def print_guid_mappings(self, show_all: bool = False, guid_filter: str = None):
        """
        Print GUID to asset mappings in a readable format.
        
        Args:
            show_all: If True, show all keys. If False, only show GUIDs (32 hex chars)
            guid_filter: If provided, only show entries matching this GUID
        """
        mappings = self.get_asset_mappings()
        
        print(f"\n{'='*70}")
        print(f"Asset GUID Mappings")
        print(f"{'='*70}\n")
        
        # Group by bundle
        bundle_to_assets = defaultdict(list)
        
        for key, locations in sorted(mappings.items()):
            # Check if this is a GUID (32 hex characters)
            is_guid = len(key) == 32 and all(c in '0123456789abcdefABCDEF' for c in key)
            
            # Filter logic
            if guid_filter and key != guid_filter:
                continue
            
            if not show_all and not is_guid:
                continue
            
            for location in locations:
                bundle_path = location.get('internal_id', 'Unknown')
                bundle_to_assets[bundle_path].append({
                    'key': key,
                    'is_guid': is_guid,
                    'resource_type': location.get('resource_type', 'Unknown'),
                    'provider': location.get('provider', 'Unknown'),
                    'primary_key': location.get('primary_key', key),
                    'has_dependencies': location.get('has_dependencies', False),
                    'dependency_key': location.get('dependency_key', None)
                })
        
        # Print grouped by bundle
        for bundle_path, assets in sorted(bundle_to_assets.items()):
            print(f"\n📦 Bundle: {bundle_path}")
            print(f"   Assets ({len(assets)}):")
            
            for asset in assets:
                key_type = "GUID" if asset['is_guid'] else "Address/Label"
                print(f"   └─ [{key_type}] {asset['key']}")
                print(f"      Type: {asset['resource_type']}")
                print(f"      Provider: {asset['provider'].split('.')[-1] if '.' in asset['provider'] else asset['provider']}")
                if asset['primary_key'] != asset['key']:
                    print(f"      Primary Key: {asset['primary_key']}")
                if asset['has_dependencies']:
                    print(f"      Dependencies: {asset['dependency_key']}")
                print()
    
    def export_to_csv(self, output_path: str):
        """Export mappings to CSV file"""
        import csv
        
        mappings = self.get_asset_mappings()
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Key', 'Type', 'Bundle_Path', 'Resource_Type', 'Provider', 'Has_Dependencies', 'Dependency_Key'])
            
            for key, locations in sorted(mappings.items()):
                is_guid = len(key) == 32 and all(c in '0123456789abcdefABCDEF' for c in key)
                key_type = 'GUID' if is_guid else 'Address/Label'
                
                for location in locations:
                    writer.writerow([
                        key,
                        key_type,
                        location.get('internal_id', ''),
                        location.get('resource_type', ''),
                        location.get('provider', ''),
                        location.get('has_dependencies', False),
                        location.get('dependency_key', '')
                    ])
        
        print(f"✅ Exported to: {output_path}")
    
    def export_to_json(self, output_path: str):
        """Export mappings to JSON file"""
        mappings = self.get_asset_mappings()
        
        # Convert to serializable format
        output = {
            'catalog_id': self.catalog_data.get('m_LocatorId', 'Unknown'),
            'mappings': mappings,
            'summary': {
                'total_keys': len(self.keys),
                'total_locations': len(self.locations),
                'total_bundles': len(self.internal_ids)
            }
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)
        
        print(f"✅ Exported to: {output_path}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Parse Unity Addressables catalog.json and extract asset GUID mappings',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse catalog and show GUIDs only
  python parse_catalog.py catalog.json
  
  # Show all keys (GUIDs, addresses, labels)
  python parse_catalog.py catalog.json --all
  
  # Filter by specific GUID
  python parse_catalog.py catalog.json --guid 00000000000000000000000000000000
  
  # Export to CSV
  python parse_catalog.py catalog.json --csv output.csv
  
  # Export to JSON
  python parse_catalog.py catalog.json --json output.json
        """
    )
    
    parser.add_argument('catalog', help='Path to catalog.json file')
    parser.add_argument('--all', action='store_true', help='Show all keys (not just GUIDs)')
    parser.add_argument('--guid', help='Filter by specific GUID')
    parser.add_argument('--csv', help='Export to CSV file')
    parser.add_argument('--json-out', help='Export to JSON file')
    parser.add_argument('--summary-only', action='store_true', help='Only show summary')
    
    args = parser.parse_args()
    
    # Parse catalog
    parser_obj = AddressablesCatalogParser(args.catalog)
    
    print(f"Loading catalog: {args.catalog}")
    if not parser_obj.load_catalog():
        sys.exit(1)
    
    print("Parsing catalog data...")
    if not parser_obj.parse_catalog():
        sys.exit(1)
    
    # Print summary
    parser_obj.print_summary()
    
    # Export or print
    if args.csv:
        parser_obj.export_to_csv(args.csv)
    
    if args.json_out:
        parser_obj.export_to_json(args.json_out)
    
    if not args.summary_only and not args.csv and not args.json_out:
        parser_obj.print_guid_mappings(show_all=args.all, guid_filter=args.guid)


if __name__ == '__main__':
    main()
