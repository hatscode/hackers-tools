# BlindElephant - Web Application Fingerprinter

Static file fingerprinting tool for identifying web application versions and components.

## Installation

```bash
# Clone repository
git clone https://github.com/lokifer/BlindElephant.git
cd BlindElephant/src

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x BlindElephant.py
```

## Basic Usage

```bash
# WordPress fingerprinting
python BlindElephant.py http://example.com wordpress

# Joomla fingerprinting  
python BlindElephant.py http://example.com joomla

# Drupal fingerprinting
python BlindElephant.py http://example.com drupal

# Generic web application
python BlindElephant.py http://example.com generic
```

## Supported Applications

### Content Management Systems
- WordPress (all major versions)
- Joomla (1.5.x through 3.x)
- Drupal (6.x through 8.x)
- TYPO3
- SilverStripe

### E-commerce Platforms
- Magento
- osCommerce
- Zen Cart
- OpenCart

### Frameworks and Libraries
- jQuery versions
- Prototype library
- MooTools framework
- ExtJS versions

## Advanced Options

```bash
# Specify version range
python BlindElephant.py http://example.com wordpress 3.0 3.9

# Update fingerprint database
python BlindElephant.py --update

# List available plugins
python BlindElephant.py --list

# Custom fingerprint location
python BlindElephant.py http://example.com wordpress --pluginDir /custom/path
```

## Fingerprinting Method

### Static File Analysis
- JavaScript file checksums
- CSS file fingerprints
- Image file hashes
- Configuration file signatures

### Version Comparison
- Database of known file signatures
- Version-specific file differences
- Changelog analysis
- Build number detection

## Output Options

```bash
# Verbose output
python BlindElephant.py http://example.com wordpress --verbose

# Quiet mode
python BlindElephant.py http://example.com wordpress --quiet

# Custom output format
python BlindElephant.py http://example.com wordpress --output json
```

## Database Management

### Fingerprint Database
- Pre-built signature database
- Regular updates available
- Custom signature creation
- Community contributions

### Accuracy Metrics
- Confidence scoring
- Multiple version possibilities
- Partial match reporting

## Integration Capabilities

### Command Line
- Scriptable execution
- Batch processing support
- Exit code reporting

### API Integration
- Python module import
- Custom script integration
- Automated scanning workflows

## Limitations

### Network Dependencies
- Requires direct file access
- May be blocked by CDNs
- Sensitive to caching mechanisms

### Detection Avoidance
- Custom file modifications can break fingerprinting
- Non-standard installations may not match
- Heavily customized applications challenging

Reliable for standard installations with minimal customization.
