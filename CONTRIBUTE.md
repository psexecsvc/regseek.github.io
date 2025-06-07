# Contributing

### Ways to Contribute$

1. **Add new artifacts** using the template
2. **Improve existing artifacts** with better descriptions or tools
3. **Fix bugs** in the web interface or build system
4. **Enhance documentation** and examples
5. **Suggest new features** via GitHub issues

### Contribution Guidelines

- Follow the YAML template structure
- Include comprehensive forensic value descriptions
- Provide real-world examples when possible
- Add relevant analysis tools with URLs
- Test your changes locally before submitting

### Using the Template

1. Copy the template:

   ```bash
   cp artifacts/_template.yml artifacts/category/your-artifact.yml
   ```

2. Fill in all required fields:

   - `title`: Clear, descriptive name
   - `category`: One of the supported categories
   - `description`: Brief forensic value summary
   - `paths`: Registry paths (array)
   - `details`: Comprehensive information object
   - `metadata`: Classification and reference data

3. Validate your artifact:
   ```bash
   python scripts/validate.py artifacts/category/your-artifact.yml
   ```

### Required Fields

```yaml
title: "Descriptive Artifact Name"
category: "execution|network|usb|user-activity|persistence|system|security|cloud|browser|malware|mobile|virtualization|communication"
description: "Brief description focusing on forensic value"
paths:
  - "HKLM\\Path\\To\\Registry\\Key"
details:
  what: "What Windows stores here"
  forensic_value: "Why investigators care"
  structure: "Data format and encoding"
  examples: ["Example values"]
  tools: [{ "name": "Tool Name", "url": "https://..." }]
```

### Enhanced Metadata

```yaml
metadata:
  criticality: "high|medium|low"
  investigation_types:
    - "malware-analysis"
    - "data-exfiltration"
  windows_versions:
    - "Windows 10"
    - "Windows 11"
  tags: ["keyword1", "keyword2"]
```
