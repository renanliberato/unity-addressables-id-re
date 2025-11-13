# Unity Addressables ID Reverse Engineer

🔍 **Decode the hidden connections between Unity Addressables assets and their serialized references**

Ever wondered why `AssetReference.m_AssetGuid` doesn't match the actual asset GUID in Addressables? This tool cracks Unity's Addressables catalog format to reveal the true mapping between serialized IDs and their corresponding assets.

## 🎯 The Problem

When Unity serializes `AssetReference` fields in Addressables builds, it stores a **different GUID** than the asset's actual GUID. This makes reverse engineering asset references nearly impossible:

```csharp
// Serialized in your build
public AssetReference myReference; // Contains m_AssetGuid that doesn't match the real asset GUID
```

Traditional asset lookup methods fail because:
- Standard asset GUIDs ≠ Addressables reference GUIDs
- The mapping is buried in base64-encoded binary data
- Unity's internal catalog format is undocumented

## 🚀 The Solution

This tool reverse-engineers Unity's `catalog.json` format to expose the complete mapping matrix:

```
Serialized Reference GUID → Real Asset GUID → Bundle Path → Asset Type
```

## ⚡ Quick Start

```bash
# Extract catalog from Android APK
unzip game.apk -d extracted/
python parse_catalog.py extracted/assets/aa/Android/catalog.json

# Find what a serialized GUID actually points to
python parse_catalog.py catalog.json --guid 00000000000000000000000000000000

# Export complete asset inventory
python parse_catalog.py catalog.json --json-out asset_inventory.json
```

## 🔬 What It Uncovers

### Asset Reference Resolution
```bash
python parse_catalog.py catalog.json --guid 00000000000000000000000000000000
```

**Output:**
```
📦 Bundle: Assets/FancyAsset.prefab
   └─ [GUID] 00000000000000000000000000000000
      Type: GameObject
      Provider: BundledAssetProvider
      Dependencies: -0000000000
```

### Bundle Content Analysis
```bash
python parse_catalog.py catalog.json --csv bundle_analysis.csv
```

Reveals:
- **20,000 total keys** in your catalog
- **12,000 asset locations** 
- **11,000 unique bundle paths**
- **80 different resource types**

### Dependency Chain Mapping
Uncovers how assets reference each other across bundles:
```
Prefab Bundle → Material Bundle → Texture Bundle → Shader Bundle
```

## 🛠️ Advanced Usage

### Reverse Engineering Workflow

1. **Extract Serialized References**
   ```bash
   # From your save files or ScriptableObjects
   grep -r "m_AssetGuid" ./save_data/
   ```

2. **Decode Real Assets**
   ```bash
   python parse_catalog.py catalog.json --guid <serialized_guid>
   ```

3. **Map Complete Asset Graph**
   ```bash
   python parse_catalog.py catalog.json --all | grep -E "(GameObject|Texture2D|Material)"
   ```

### Programmatic Integration
```python
from parse_catalog import AddressablesCatalogParser

parser = AddressablesCatalogParser('catalog.json')
parser.load_catalog()
parser.parse_catalog()

# Resolve any reference GUID
def resolve_reference(serialized_guid):
    mappings = parser.get_asset_mappings()
    return mappings.get(serialized_guid, [])
```

## 🧩 Technical Deep Dive

### Cracking the Binary Format

Unity's catalog uses multiple layers of encoding:

```
catalog.json
├─ m_KeyDataString (base64 → binary)
│  ├─ Type 0: [0x00][4-byte length][UTF-8 string]
│  ├─ Type 1: [0x01][7-bit encoded length][UTF-8 string] 
│  └─ Type 4: [0x04] (markers)
├─ m_BucketDataString (base64 → hash table)
├─ m_EntryDataString (base64 → location data)
└─ m_ExtraDataString (base64 → dependency info)
```

### Key Types Discovered

- **GUID Keys**: `6eb2d8100f3dd174bbf51049089ab7e7` (32-char hex)
- **Path Keys**: `Assets/FancyAsset.prefab`
- **Label Keys**: `"Default"`, `"Downloadable"`
- **Dependency Keys**: `-0000000000` (integer hashes)

## 📈 Performance

Processes large catalogs efficiently:
- **20,000 keys** parsed in **< 2 seconds**
- **Zero external dependencies** - pure Python

## 🔧 Installation

```bash
# Clone the tool
git clone https://github.com/your-repo/unity-addressables-id-re.git
cd unity-addressables-id-re

# No dependencies needed - Python 3.6+ only
python parse_catalog.py --help
```

## 📄 License

MIT License - Use freely for modding, reverse engineering, and development.
