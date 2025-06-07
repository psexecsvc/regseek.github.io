#!/usr/bin/env python3
"""
Validate artifact YAML files against the enhanced RegSeek schema
"""

import yaml
import sys
from pathlib import Path
from jsonschema import validate, ValidationError

# Enhanced schema for artifact validation
ARTIFACT_SCHEMA = {
    "type": "object",
    "required": ["title", "category", "description", "paths", "details"],
    "properties": {
        "title": {"type": "string", "minLength": 5},
        "category": {
            "type": "string",
            "enum": [
                "execution", "network", "usb", "user-activity", "persistence", 
                "system", "security", "cloud", "browser", "malware", "mobile", 
                "virtualization", "communication"
            ]
        },
        "description": {"type": "string", "minLength": 10},
        "paths": {
            "type": "array",
            "items": {"type": "string", "pattern": "^HK(LM|CU|CR|U|CC)\\\\"},
            "minItems": 1
        },
        "details": {
            "type": "object",
            "required": ["what", "forensic_value", "structure", "examples", "tools"],
            "properties": {
                "what": {"type": "string", "minLength": 20},
                "forensic_value": {"type": "string", "minLength": 20},
                "structure": {"type": "string", "minLength": 10},
                "examples": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1
                },
                "tools": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": {"type": "string"},
                            "url": {"type": "string", "format": "uri"},
                            "description": {"type": "string"}
                        }
                    },
                    "minItems": 1
                }
            }
        },
        "metadata": {
            "type": "object",
            "properties": {
                "windows_versions": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "introduced": {"type": "string"},
                "deprecated": {"type": "string"},
                "criticality": {
                    "type": "string",
                    "enum": ["high", "medium", "low"]
                },
                "investigation_types": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": [
                            "malware-analysis", "data-exfiltration", "insider-threat",
                            "incident-response", "timeline-analysis", "privilege-escalation",
                            "lateral-movement", "persistence-analysis", "behavioral-analysis"
                        ]
                    }
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "references": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["title"],
                        "properties": {
                            "title": {"type": "string"},
                            "url": {"type": "string", "format": "uri"},
                            "type": {
                                "type": "string",
                                "enum": ["official", "research", "blog", "tool"]
                            }
                        }
                    }
                },
                "retention": {
                    "type": "object",
                    "properties": {
                        "default_location": {"type": "string"},
                        "persistence": {"type": "string"},
                        "volatility": {"type": "string"}
                    }
                },
                "related_artifacts": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            }
        },
        "author": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "github": {"type": "string"},
                "x": {"type": "string"},
                "email": {"type": "string", "format": "email"},
                "organization": {"type": "string"}
            }
        },
        "contribution": {
            "type": "object",
            "properties": {
                "date_added": {"type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}$"},
                "last_updated": {"type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}$"},
                "version": {"type": "string"},
                "reviewed_by": {"type": "string"}
            }
        }
    }
}

def validate_artifact(file_path):
    """Validate a single artifact file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            artifact = yaml.safe_load(f)
        
        # Basic structure validation
        validate(instance=artifact, schema=ARTIFACT_SCHEMA)
        
        # Additional custom validations
        validation_warnings = []
        
        # Check if paths look like valid registry paths
        for path in artifact.get('paths', []):
            if not any(path.startswith(hive) for hive in ['HKLM\\', 'HKCU\\', 'HKCR\\', 'HKU\\', 'HKCC\\']):
                validation_warnings.append(f"Path may not be valid registry path: {path}")
        
        # Check if tools have URLs (recommended)
        tools = artifact.get('details', {}).get('tools', [])
        tools_without_urls = 0
        for tool in tools:
            if isinstance(tool, dict) and 'name' in tool and 'url' not in tool:
                tools_without_urls += 1
        
        if tools_without_urls > 0:
            validation_warnings.append(f"{tools_without_urls} tool(s) missing URL (recommended)")
        
        # Check for criticality level (recommended)
        if 'metadata' in artifact and 'criticality' not in artifact['metadata']:
            validation_warnings.append("Criticality level not specified (recommended)")
        
        # Check for investigation types
        if 'metadata' in artifact and 'investigation_types' not in artifact['metadata']:
            validation_warnings.append("Investigation types not specified (recommended)")
        
        # Print results
        if validation_warnings:
            print(f"✓ {file_path} is valid but has recommendations:")
            for warning in validation_warnings:
                print(f"   - {warning}")
        else:
            print(f"✓ {file_path} is valid and complete")
        
        return True
        
    except ValidationError as e:
        print(f"✗ {file_path} validation failed:")
        print(f"   {e.message}")
        if hasattr(e, 'absolute_path') and e.absolute_path:
            print(f"   Path: {' -> '.join(str(x) for x in e.absolute_path)}")
        return False
    except Exception as e:
        print(f"✗ {file_path} error: {e}")
        return False

def main():
    print(" RegSeek Artifact Validator")
    print("=" * 40)
    
    if len(sys.argv) > 1:
        # Validate specific file
        file_path = Path(sys.argv[1])
        if not file_path.exists():
            print(f" File not found: {file_path}")
            sys.exit(1)
            
        print(f"Validating: {file_path}")
        if not validate_artifact(file_path):
            sys.exit(1)
    else:
        # Validate all artifacts
        artifacts_dir = Path("artifacts")
        if not artifacts_dir.exists():
            print(f" Artifacts directory not found: {artifacts_dir}")
            sys.exit(1)
            
        failed = []
        validated = []
        
        for artifact_file in artifacts_dir.rglob("*.yml"):
            if artifact_file.name.startswith('_'):
                print(f"  Skipping template: {artifact_file}")
                continue
                
            validated.append(artifact_file)
            if not validate_artifact(artifact_file):
                failed.append(artifact_file)
        
        # Summary
        print("\n" + "=" * 40)
        print(" Validation Summary:")
        print("=" * 40)
        print(f"Files validated: {len(validated)}")
        print(f" Passed: {len(validated) - len(failed)}")
        print(f" Failed: {len(failed)}")
        
        if failed:
            print(f"\n {len(failed)} artifacts failed validation:")
            for f in failed:
                print(f"   - {f}")
            sys.exit(1)
        else:
            print(f"\n🎉 All {len(validated)} artifacts are valid!")

if __name__ == "__main__":
    main()
