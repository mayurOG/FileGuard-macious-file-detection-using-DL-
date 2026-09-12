"""
PE Feature Extraction + Threat Indicator Engine
Author: Mayur Nhavalde

Extracts deep PE header/section/import/resource features and computes
a set of human-readable threat indicators with severity tags.
"""

import pefile
import os
import array
import math
import sys
import numpy as np
from typing import Dict, List, Any


# ── Entropy helpers ───────────────────────────────────────────────────────────

def get_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0-8 bits)."""
    if len(data) == 0:
        return 0.0
    occurrences = array.array("L", [0] * 256)
    for x in data:
        occurrences[x if isinstance(x, int) else ord(x)] += 1
    entropy = 0.0
    for x in occurrences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)
    return entropy


def get_resources(pe: pefile.PE) -> List[List[float]]:
    """Extract list of [entropy, size] pairs from PE resources."""
    resources: List[List[float]] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return resources
    try:
        for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if not hasattr(rtype, "directory"):
                continue
            for rid in rtype.directory.entries:
                if not hasattr(rid, "directory"):
                    continue
                for rlang in rid.directory.entries:
                    data = pe.get_data(
                        rlang.data.struct.OffsetToData,
                        rlang.data.struct.Size,
                    )
                    resources.append([get_entropy(data), rlang.data.struct.Size])
    except Exception:
        pass
    return resources


def get_version_info(pe: pefile.PE) -> Dict[str, Any]:
    """Extract version-info strings and fixed file info fields."""
    res: Dict[str, Any] = {}
    if not hasattr(pe, "FileInfo"):
        return res
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == b"StringFileInfo":
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == b"VarFileInfo":
            for var in fileinfo.Var:
                items = list(var.entry.items())
                if items:
                    res[items[0][0]] = items[0][1]
    if hasattr(pe, "VS_FIXEDFILEINFO"):
        fi = pe.VS_FIXEDFILEINFO
        res["flags"]           = fi.FileFlags
        res["os"]              = fi.FileOS
        res["type"]            = fi.FileType
        res["file_version"]    = fi.FileVersionLS
        res["product_version"] = fi.ProductVersionLS
        res["signature"]       = fi.Signature
        res["struct_version"]  = fi.StrucVersion
    return res


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_infos(fpath: str) -> Dict[str, Any]:
    """
    Parse a PE file and return the full numeric feature dictionary
    used as model input.
    """
    res: Dict[str, Any] = {}
    pe = pefile.PE(fpath)

    # File header
    res["Machine"]              = pe.FILE_HEADER.Machine
    res["SizeOfOptionalHeader"] = pe.FILE_HEADER.SizeOfOptionalHeader
    res["Characteristics"]      = pe.FILE_HEADER.Characteristics

    # Optional header
    oh = pe.OPTIONAL_HEADER
    res["MajorLinkerVersion"]         = oh.MajorLinkerVersion
    res["MinorLinkerVersion"]         = oh.MinorLinkerVersion
    res["SizeOfCode"]                 = oh.SizeOfCode
    res["SizeOfInitializedData"]      = oh.SizeOfInitializedData
    res["SizeOfUninitializedData"]    = oh.SizeOfUninitializedData
    res["AddressOfEntryPoint"]        = oh.AddressOfEntryPoint
    res["BaseOfCode"]                 = oh.BaseOfCode
    try:
        res["BaseOfData"] = oh.BaseOfData
    except AttributeError:
        res["BaseOfData"] = 0
    res["ImageBase"]                  = oh.ImageBase
    res["SectionAlignment"]           = oh.SectionAlignment
    res["FileAlignment"]              = oh.FileAlignment
    res["MajorOperatingSystemVersion"]= oh.MajorOperatingSystemVersion
    res["MinorOperatingSystemVersion"]= oh.MinorOperatingSystemVersion
    res["MajorImageVersion"]          = oh.MajorImageVersion
    res["MinorImageVersion"]          = oh.MinorImageVersion
    res["MajorSubsystemVersion"]      = oh.MajorSubsystemVersion
    res["MinorSubsystemVersion"]      = oh.MinorSubsystemVersion
    res["SizeOfImage"]                = oh.SizeOfImage
    res["SizeOfHeaders"]              = oh.SizeOfHeaders
    res["CheckSum"]                   = oh.CheckSum
    res["Subsystem"]                  = oh.Subsystem
    res["DllCharacteristics"]         = oh.DllCharacteristics
    res["SizeOfStackReserve"]         = oh.SizeOfStackReserve
    res["SizeOfStackCommit"]          = oh.SizeOfStackCommit
    res["SizeOfHeapReserve"]          = oh.SizeOfHeapReserve
    res["SizeOfHeapCommit"]           = oh.SizeOfHeapCommit
    res["LoaderFlags"]                = oh.LoaderFlags
    res["NumberOfRvaAndSizes"]        = oh.NumberOfRvaAndSizes

    # Sections
    res["SectionsNb"] = len(pe.sections)
    entropies     = [s.get_entropy() for s in pe.sections]
    raw_sizes     = [s.SizeOfRawData    for s in pe.sections]
    virtual_sizes = [s.Misc_VirtualSize for s in pe.sections]

    res["SectionsMeanEntropy"]    = sum(entropies) / len(entropies)
    res["SectionsMinEntropy"]     = min(entropies)
    res["SectionsMaxEntropy"]     = max(entropies)
    res["SectionsMeanRawsize"]    = sum(raw_sizes)  / len(raw_sizes)
    res["SectionsMinRawsize"]     = min(raw_sizes)
    res["SectionsMaxRawsize"]     = max(raw_sizes)
    res["SectionsMeanVirtualsize"]= sum(virtual_sizes) / len(virtual_sizes)
    res["SectionsMinVirtualsize"] = min(virtual_sizes)
    res["SectionMaxVirtualsize"]  = max(virtual_sizes)

    # Imports
    try:
        res["ImportsNbDLL"]     = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports                 = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res["ImportsNb"]        = len(imports)
        res["ImportsNbOrdinal"] = len([x for x in imports if x.name is None])
    except AttributeError:
        res["ImportsNbDLL"]     = 0
        res["ImportsNb"]        = 0
        res["ImportsNbOrdinal"] = 0

    # Exports
    try:
        res["ExportNb"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        res["ExportNb"] = 0

    # Resources
    resources = get_resources(pe)
    res["ResourcesNb"] = len(resources)
    if resources:
        ent   = [r[0] for r in resources]
        sizes = [r[1] for r in resources]
        res["ResourcesMeanEntropy"] = sum(ent)   / len(ent)
        res["ResourcesMinEntropy"]  = min(ent)
        res["ResourcesMaxEntropy"]  = max(ent)
        res["ResourcesMeanSize"]    = sum(sizes) / len(sizes)
        res["ResourcesMinSize"]     = min(sizes)
        res["ResourcesMaxSize"]     = max(sizes)
    else:
        res["ResourcesMeanEntropy"] = 0
        res["ResourcesMinEntropy"]  = 0
        res["ResourcesMaxEntropy"]  = 0
        res["ResourcesMeanSize"]    = 0
        res["ResourcesMinSize"]     = 0
        res["ResourcesMaxSize"]     = 0

    # Load config
    try:
        res["LoadConfigurationSize"] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        res["LoadConfigurationSize"] = 0

    # Version info
    try:
        res["VersionInformationSize"] = len(get_version_info(pe).keys())
    except AttributeError:
        res["VersionInformationSize"] = 0

    pe.close()
    return res


# ── Threat indicator engine ───────────────────────────────────────────────────

# Known suspicious import DLLs and functions (common in malware)
_SUSPICIOUS_IMPORTS = {
    "kernel32.dll": [
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
        "CreateRemoteThread", "OpenProcess", "LoadLibraryA",
        "GetProcAddress", "SetWindowsHookEx",
    ],
    "ntdll.dll": [
        "NtUnmapViewOfSection", "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory", "RtlDecompressBuffer",
    ],
    "ws2_32.dll": ["connect", "send", "recv", "WSAStartup"],
    "wininet.dll": ["InternetOpenA", "InternetConnectA", "HttpSendRequestA"],
    "advapi32.dll": ["RegSetValueEx", "RegCreateKeyEx", "CryptEncrypt"],
}

_HIGH_ENTROPY_THRESHOLD = 6.8   # packed / encrypted sections
_SUSPICIOUS_SECTION_NAMES = {
    b".upx0", b".upx1", b"UPX0", b"UPX1",
    b"themida", b".nsp0", b".nsp1",
}


def compute_threat_indicators(features: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Analyse extracted PE features and return a list of threat indicators.
    Each indicator has: { name, description, severity }
    Severity: INFO | LOW | MEDIUM | HIGH | CRITICAL
    """
    indicators: List[Dict[str, str]] = []

    # 1. High section entropy → possible packing / encryption
    max_ent = features.get("SectionsMaxEntropy", 0)
    if max_ent >= _HIGH_ENTROPY_THRESHOLD:
        indicators.append({
            "name": "High Section Entropy",
            "description": (
                f"Max section entropy is {max_ent:.2f} (≥{_HIGH_ENTROPY_THRESHOLD}). "
                "This is a strong indicator of packing or encryption — common in obfuscated malware."
            ),
            "severity": "HIGH" if max_ent < 7.5 else "CRITICAL",
            "mitre": "T1027 – Obfuscated Files or Information",
        })

    # 2. No imports (common trick: resolve at runtime)
    if features.get("ImportsNb", 0) == 0:
        indicators.append({
            "name": "No Static Imports",
            "description": (
                "The file has zero static imports. Malware often resolves APIs "
                "dynamically (GetProcAddress) to evade static analysis."
            ),
            "severity": "HIGH",
            "mitre": "T1027.001 – Binary Padding / Dynamic Resolution",
        })

    # 3. High ordinal imports (evasion tactic)
    ordinal_ratio = 0.0
    if features.get("ImportsNb", 0) > 0:
        ordinal_ratio = features.get("ImportsNbOrdinal", 0) / features["ImportsNb"]
    if ordinal_ratio > 0.5:
        indicators.append({
            "name": "High Ordinal Import Ratio",
            "description": (
                f"{ordinal_ratio*100:.1f}% of imports use ordinals instead of names, "
                "making static analysis harder."
            ),
            "severity": "MEDIUM",
            "mitre": "T1036 – Masquerading",
        })

    # 4. Missing checksum (common in malformed/trojanised binaries)
    if features.get("CheckSum", 0) == 0:
        indicators.append({
            "name": "Missing PE Checksum",
            "description": (
                "The PE checksum is zero. Legitimate system binaries always have "
                "a valid checksum; its absence is suspicious."
            ),
            "severity": "MEDIUM",
            "mitre": "T1036.005 – Match Legitimate Name or Location",
        })

    # 5. No version information
    if features.get("VersionInformationSize", 0) == 0:
        indicators.append({
            "name": "No Version Information",
            "description": (
                "The file contains no version-info resource block. "
                "Most legitimate Windows applications include this metadata."
            ),
            "severity": "LOW",
            "mitre": "T1036 – Masquerading",
        })

    # 6. Many exports (potential DLL hijack / injector)
    if features.get("ExportNb", 0) > 50:
        indicators.append({
            "name": "Unusually High Export Count",
            "description": (
                f"{features['ExportNb']} exported symbols detected. "
                "A large export table may indicate a malicious DLL or proxy DLL."
            ),
            "severity": "MEDIUM",
            "mitre": "T1574.001 – DLL Search Order Hijacking",
        })

    # 7. High resource entropy (data hidden in resources)
    res_max_ent = features.get("ResourcesMaxEntropy", 0)
    if res_max_ent >= _HIGH_ENTROPY_THRESHOLD:
        indicators.append({
            "name": "High Resource Entropy",
            "description": (
                f"Max resource entropy is {res_max_ent:.2f}. "
                "Encrypted payloads are sometimes embedded in PE resources."
            ),
            "severity": "HIGH",
            "mitre": "T1027 – Obfuscated Files or Information",
        })

    # 8. Tiny SizeOfCode (possible hollow/shellcode stub)
    if 0 < features.get("SizeOfCode", -1) < 512:
        indicators.append({
            "name": "Unusually Small Code Section",
            "description": (
                f"SizeOfCode is only {features['SizeOfCode']} bytes. "
                "This may indicate a loader stub or process-hollowing dropper."
            ),
            "severity": "HIGH",
            "mitre": "T1055 – Process Injection",
        })

    # 9. Non-standard subsystem
    subsystem = features.get("Subsystem", 2)
    if subsystem not in (1, 2, 3):   # NATIVE, GUI, CUI
        indicators.append({
            "name": "Unusual PE Subsystem",
            "description": (
                f"Subsystem value is {subsystem} (not standard GUI/Console/Native). "
                "Uncommon subsystems are used by rootkits and drivers."
            ),
            "severity": "MEDIUM",
            "mitre": "T1014 – Rootkit",
        })

    # 10. All clear
    if not indicators:
        indicators.append({
            "name": "No Obvious Static Indicators",
            "description": (
                "No high-risk static PE indicators were detected. "
                "Always combine with dynamic/behavioural analysis for full assurance."
            ),
            "severity": "INFO",
            "mitre": "N/A",
        })

    return indicators


# ── CLI entry point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    from tensorflow.keras.models import load_model, Model as KModel

    if len(sys.argv) < 2:
        print("Usage: python Final_Testing.py <path_to_exe>")
        sys.exit(1)

    autoencoder   = load_model("auto_model.keras")
    ann_model     = load_model("maliNN_model.keras")
    encoder_model = KModel(
        inputs=autoencoder.input,
        outputs=autoencoder.get_layer("bottleneck").output,
    )

    data           = extract_infos(sys.argv[1])
    indicators     = compute_threat_indicators(data)
    pe_features    = np.array([list(data.values())], dtype=np.float32)
    bottleneck     = encoder_model.predict(pe_features, verbose=0)
    prediction_val = ann_model.predict(bottleneck, verbose=0)[0][0]

    verdict = "MALICIOUS" if prediction_val > 0.5 else "LEGITIMATE"
    print(f"\n{'='*50}")
    print(f"  File      : {os.path.basename(sys.argv[1])}")
    print(f"  Verdict   : {verdict}")
    print(f"  Confidence: {prediction_val:.4f}")
    print(f"\n  Threat Indicators ({len(indicators)}):")
    for ind in indicators:
        print(f"    [{ind['severity']:8s}] {ind['name']}")
        print(f"             {ind['description'][:80]}...")
    print(f"{'='*50}\n")
